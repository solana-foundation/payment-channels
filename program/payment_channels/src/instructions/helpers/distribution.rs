#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{Address, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::state::Transmutable;

/// Maximum number of distribution recipients per channel.
pub const MAX_DISTRIBUTION_RECIPIENTS: usize = 32;

/// One entry in the distribution plan committed at `open`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributionEntry {
    pub recipient: Address,
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    amount: [u8; 8],
}

impl DistributionEntry {
    #[inline(always)]
    pub fn amount(&self) -> u64 {
        u64::from_le_bytes(self.amount)
    }
}

/// Packed distribution plan committed at `open` and verified by `distribute`.
///
/// Wire layout: `count(1) | entries(32×40)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributionRecipients {
    /// Number of active entries (1–32).
    pub count: u8,
    // Codama requires a literal here; keep in sync with MAX_DISTRIBUTION_RECIPIENTS.
    pub entries: [DistributionEntry; 32],
}

// Fails to compile if the literal above drifts from MAX_DISTRIBUTION_RECIPIENTS.
const _: () = assert!(
    MAX_DISTRIBUTION_RECIPIENTS == 32,
    "update DistributionRecipients::entries literal to match MAX_DISTRIBUTION_RECIPIENTS",
);

impl DistributionRecipients {
    /// Validates `count` is in `1..=MAX_DISTRIBUTION_RECIPIENTS`.
    pub fn validate(&self) -> Result<usize, ProgramError> {
        let n = self.count as usize;
        if n == 0 || n > MAX_DISTRIBUTION_RECIPIENTS {
            return Err(PaymentChannelsError::InvalidRecipientCount.into());
        }
        Ok(n)
    }

    /// Raw bytes of `count(1) || entries[0..count](count×40)` — the blake3
    /// preimage for [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    #[inline(always)]
    pub fn preimage(&self) -> &[u8] {
        let n = self.count as usize;
        &self.as_bytes()[..1 + n * 40]
    }

    pub fn preimage_hash(&self) -> [u8; 32] {
        #[allow(unused_variables)]
        let input = self.preimage();
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let mut out = [0u8; 32];
            let slices: &[&[u8]] = &[input];
            // SAFETY: sol_blake3 fills exactly 32 bytes; each &[u8] is a fat pointer
            // (ptr, len) matching the SolBytes C layout on 64-bit BPF.
            unsafe {
                pinocchio::syscalls::sol_blake3(slices.as_ptr().cast::<u8>(), 1, out.as_mut_ptr());
            }
            out
        }
        #[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), test))]
        {
            blake3::hash(input).into()
        }
        #[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), not(test)))]
        {
            panic!("sol_blake3 syscall is unavailable on non-BPF targets");
        }
    }
}

unsafe impl Transmutable for DistributionRecipients {
    const LEN: usize = size_of::<Self>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_recipients(count: u8) -> DistributionRecipients {
        let entry = DistributionEntry {
            recipient: Address::default(),
            amount: 500u64.to_le_bytes(),
        };
        DistributionRecipients {
            count,
            entries: [entry; MAX_DISTRIBUTION_RECIPIENTS],
        }
    }

    #[test]
    fn validate_zero_count_rejected() {
        assert!(make_recipients(0).validate().is_err());
    }

    #[test]
    fn validate_max_count_accepted() {
        assert_eq!(
            make_recipients(MAX_DISTRIBUTION_RECIPIENTS as u8)
                .validate()
                .unwrap(),
            MAX_DISTRIBUTION_RECIPIENTS,
        );
    }

    #[test]
    fn validate_over_max_rejected() {
        let r = DistributionRecipients {
            count: MAX_DISTRIBUTION_RECIPIENTS as u8 + 1,
            entries: [DistributionEntry {
                recipient: Address::default(),
                amount: [0u8; 8],
            }; MAX_DISTRIBUTION_RECIPIENTS],
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn preimage_length_matches_count() {
        for n in 1..=MAX_DISTRIBUTION_RECIPIENTS {
            let r = make_recipients(n as u8);
            assert_eq!(r.preimage().len(), 1 + n * 40);
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
}
