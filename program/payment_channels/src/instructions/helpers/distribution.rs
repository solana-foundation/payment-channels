#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{Address, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::state::{Transmutable, load};

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

unsafe impl Transmutable for DistributionEntry {
    const LEN: usize = size_of::<Self>();
}

const _: () = assert!(size_of::<DistributionEntry>() == 34);
const _: () = assert!(core::mem::align_of::<DistributionEntry>() == 1);

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct LeU32([u8; size_of::<u32>()]);

impl LeU32 {
    #[inline(always)]
    fn get(&self) -> u32 {
        u32::from_le_bytes(self.0)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DistributionPreimageHeader {
    count: LeU32,
}

unsafe impl Transmutable for DistributionPreimageHeader {
    const LEN: usize = size_of::<Self>();
}

const _: () = assert!(size_of::<LeU32>() == size_of::<u32>());
const _: () = assert!(core::mem::align_of::<LeU32>() == 1);
const _: () = assert!(size_of::<DistributionPreimageHeader>() == size_of::<u32>());
const _: () = assert!(core::mem::align_of::<DistributionPreimageHeader>() == 1);

/// Borrowed view of the validated distribution preimage.
///
/// Wire layout: `count(u32 LE) || [recipient(32) || shareBps(u16 LE)] × count`.
#[derive(Debug, Clone, Copy)]
pub struct DistributionPreimage<'a> {
    /// Entries declared by the count prefix.
    pub entries: &'a [DistributionEntry],
    /// Bytes hashed into the channel's distribution commitment.
    preimage: &'a [u8],
}

impl<'a> DistributionPreimage<'a> {
    /// Parses `count || entries` and verifies the distribution invariants.
    ///
    /// The count must be at most [`MAX_DISTRIBUTION_RECIPIENTS`], the byte
    /// length must exactly match the count, each entry must have non-zero
    /// basis points, the total basis points must not exceed 10_000, and
    /// recipient owner addresses must be unique.
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < DistributionPreimageHeader::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (header_bytes, entries_bytes) = data.split_at(DistributionPreimageHeader::LEN);
        let header = unsafe { load::<DistributionPreimageHeader>(header_bytes) }
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let count = header.count.get();
        if count > MAX_DISTRIBUTION_RECIPIENTS as u32 {
            return Err(PaymentChannelsError::InvalidRecipientCount.into());
        }
        let n = count as usize;

        let expected_len = DistributionPreimageHeader::LEN
            .checked_add(
                n.checked_mul(DistributionEntry::LEN)
                    .ok_or(PaymentChannelsError::ArithmeticOverflow)?,
            )
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
        if data.len() != expected_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        let entries = if n == 0 {
            &[]
        } else {
            unsafe {
                core::slice::from_raw_parts(entries_bytes.as_ptr().cast::<DistributionEntry>(), n)
            }
        };

        let mut bps_sum = 0u32;
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

        Ok(Self {
            entries,
            preimage: data,
        })
    }

    /// Basis points reserved for the channel payee's implicit remainder share.
    #[inline(always)]
    pub fn payee_bps(&self) -> u32 {
        let bps_sum: u32 = self.entries.iter().map(|entry| entry.bps() as u32).sum();
        debug_assert!(bps_sum <= BPS_DENOMINATOR);
        BPS_DENOMINATOR - bps_sum
    }

    /// Preimage bytes hashed into [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    #[inline(always)]
    pub fn preimage(&self) -> &'a [u8] {
        self.preimage
    }

    /// Blake3 hash of the active preimage committed into the channel at `open`.
    pub fn preimage_hash(&self) -> [u8; 32] {
        super::hash::blake3(self.preimage)
    }
}

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
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;

    fn entry(byte: u8, bps: u16) -> DistributionEntry {
        DistributionEntry {
            recipient: Address::new_from_array([byte; 32]),
            bps: bps.to_le_bytes(),
        }
    }

    fn encode(count: u32, entries: &[DistributionEntry]) -> Vec<u8> {
        let mut data = Vec::with_capacity(
            DistributionPreimageHeader::LEN + entries.len() * DistributionEntry::LEN,
        );
        data.extend_from_slice(&count.to_le_bytes());
        for entry in entries {
            data.extend_from_slice(entry.recipient.as_ref());
            data.extend_from_slice(&entry.bps);
        }
        data
    }

    fn with_view<R>(count: u8, f: impl FnOnce(DistributionPreimage<'_>) -> R) -> R {
        let entries: Vec<_> = (0..count)
            .map(|i| entry(i.saturating_add(1), 100))
            .collect();
        let bytes = encode(count as u32, &entries);
        f(DistributionPreimage::load(&bytes).unwrap())
    }

    fn with_recipients_from_entries<R>(
        entries: &[DistributionEntry],
        f: impl FnOnce(DistributionPreimage<'_>) -> R,
    ) -> R {
        let bytes = encode(entries.len() as u32, entries);
        f(DistributionPreimage::load(&bytes).unwrap())
    }

    #[test]
    fn load_rejects_empty_data() {
        assert_eq!(
            DistributionPreimage::load(&[]).map(|_| ()),
            Err(ProgramError::InvalidInstructionData),
        );
    }

    #[test]
    fn load_rejects_count_above_max() {
        let data = ((MAX_DISTRIBUTION_RECIPIENTS + 1) as u32).to_le_bytes();
        assert_eq!(
            DistributionPreimage::load(&data).map(|_| ()),
            Err(ProgramError::from(
                PaymentChannelsError::InvalidRecipientCount
            )),
        );
    }

    #[test]
    fn load_rejects_truncated_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[0u8; DistributionEntry::LEN - 1]);
        assert_eq!(
            DistributionPreimage::load(&data).map(|_| ()),
            Err(ProgramError::InvalidInstructionData),
        );
    }

    #[test]
    fn load_rejects_trailing_bytes() {
        let mut data = encode(0, &[]);
        data.push(0);
        assert_eq!(
            DistributionPreimage::load(&data).map(|_| ()),
            Err(ProgramError::InvalidInstructionData),
        );
    }

    #[test]
    fn load_zero_count_accepted() {
        with_view(0, |r| {
            assert_eq!(r.entries.len(), 0);
            assert_eq!(r.payee_bps(), BPS_DENOMINATOR);
        });
    }

    #[test]
    fn load_returns_active_entries_and_payee_bps() {
        with_recipients_from_entries(&[entry(1, 2500), entry(2, 3000)], |r| {
            assert_eq!(r.entries.len(), 2);
            assert_eq!(r.payee_bps(), 4500);
        });
    }

    #[test]
    fn load_max_count_accepted() {
        with_view(MAX_DISTRIBUTION_RECIPIENTS as u8, |r| {
            assert_eq!(r.entries.len(), MAX_DISTRIBUTION_RECIPIENTS);
        });
    }

    #[test]
    fn load_full_bps_sum_accepted() {
        with_recipients_from_entries(&[entry(1, BPS_DENOMINATOR as u16)], |r| {
            assert_eq!(r.entries.len(), 1);
            assert_eq!(r.payee_bps(), 0);
        });
    }

    #[test]
    fn load_rejects_zero_bps() {
        let data = encode(1, &[entry(1, 0)]);
        assert_eq!(
            DistributionPreimage::load(&data).map(|_| ()),
            Err(ProgramError::from(PaymentChannelsError::InvalidSplitConfig)),
        );
    }

    #[test]
    fn load_rejects_over_10000_bps() {
        let data = encode(1, &[entry(1, BPS_DENOMINATOR as u16 + 1)]);
        assert_eq!(
            DistributionPreimage::load(&data).map(|_| ()),
            Err(ProgramError::from(PaymentChannelsError::InvalidSplitConfig)),
        );
    }

    #[test]
    fn preimage_length_matches_count() {
        for n in 0..=MAX_DISTRIBUTION_RECIPIENTS {
            with_view(n as u8, |r| {
                assert_eq!(
                    r.preimage().len(),
                    DistributionPreimageHeader::LEN + n * DistributionEntry::LEN,
                );
            });
        }
    }

    #[test]
    fn preimage_prefix_is_count() {
        with_view(7, |r| {
            assert_eq!(
                &r.preimage()[..DistributionPreimageHeader::LEN],
                &7u32.to_le_bytes()
            );
        });
    }

    #[test]
    fn preimage_hash_is_deterministic() {
        with_view(3, |r| {
            assert_eq!(r.preimage_hash(), r.preimage_hash());
        });
    }

    #[test]
    fn preimage_hash_differs_by_count() {
        with_recipients_from_entries(&[entry(1, 100)], |r1| {
            with_recipients_from_entries(&[entry(1, 100), entry(2, 100)], |r2| {
                assert_ne!(r1.preimage_hash(), r2.preimage_hash());
            });
        });
    }

    #[test]
    fn floor_bps_share_rounds_down() {
        assert_eq!(floor_bps_share(10, 3333).unwrap(), 3);
        assert_eq!(floor_bps_share(10, 3334).unwrap(), 3);
    }

    #[test]
    fn load_accepts_distinct_recipients() {
        with_view(3, |r| {
            assert_eq!(r.entries.len(), 3);
        });
    }

    #[test]
    fn load_rejects_duplicate_recipient() {
        let data = encode(3, &[entry(1, 100), entry(2, 100), entry(1, 100)]);
        assert_eq!(
            DistributionPreimage::load(&data).map(|_| ()),
            Err(ProgramError::from(PaymentChannelsError::DuplicateRecipient)),
        );
    }
}
