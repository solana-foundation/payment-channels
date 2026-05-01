#[cfg(feature = "idl")]
use codama::CodamaAccount;
use core::mem::size_of;
use pinocchio::error::ProgramError;

use crate::state::common::AccountDiscriminator;
use crate::state::transmutable::{Transmutable, load_mut};

/// Tombstoned channel PDA. Replaces the [`Channel`](crate::Channel) bytes via
/// in-place realloc at `distribute`'s FINALIZED branch so the address stays
/// alive forever, owned by the program. Re-init at the same seeds is rejected
/// by the system program (`CreateAccount` requires `lamports == 0`,
/// `Allocate` requires empty data + system ownership). The distinct
/// `AccountDiscriminator::ClosedChannel` is defense-in-depth: any reader
/// going through `Channel::from_account_mut` rejects on the discriminator
/// gate before any status check runs.
///
/// Layout follows the canonical Solana tombstone idiom: a single rejection
/// byte at offset 0, and zero-filled trailing bytes to satisfy the ADR-002
/// 8-byte total. Anchor's historical `[0xFF; 8]` tombstone is the same
/// shape; we use a per-program discriminator (`= 2`) instead of `0xFF`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaAccount))]
pub struct ClosedChannel {
    /// [`AccountDiscriminator::ClosedChannel`] (`= 2`). Single source of
    /// truth for the "this address is dead" signal.
    pub discriminator: u8,
    /// Zero-filled. ADR-002 mandates 8 bytes total; reserved as forward-
    /// compatible space if a future ADR claims any of these slots.
    pub reserved: [u8; 7],
}

impl ClosedChannel {
    pub const LEN: usize = size_of::<Self>();

    /// Overwrite `bytes` with the 8-byte tombstone payload. Caller is
    /// responsible for shrinking the account to [`Self::LEN`] before calling.
    pub fn write_into(bytes: &mut [u8]) -> Result<(), ProgramError> {
        // SAFETY: `ClosedChannel` is `repr(C)` with alignment 1; load_mut
        // checks length and align is verified at every load_mut call site.
        let cc = unsafe { load_mut::<Self>(bytes) }?;
        cc.discriminator = AccountDiscriminator::ClosedChannel as u8;
        cc.reserved = [0u8; 7];
        Ok(())
    }
}

unsafe impl Transmutable for ClosedChannel {
    const LEN: usize = size_of::<Self>();
}

const _: () = {
    assert!(ClosedChannel::LEN == 8);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::channel::Channel;

    #[test]
    fn len_is_eight_bytes() {
        assert_eq!(ClosedChannel::LEN, 8);
        assert_eq!(core::mem::size_of::<ClosedChannel>(), 8);
    }

    #[test]
    fn write_into_produces_expected_bytes() {
        let mut bytes = [0u8; ClosedChannel::LEN];
        ClosedChannel::write_into(&mut bytes).unwrap();
        assert_eq!(bytes, [2, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn channel_load_rejects_tombstone_buffer() {
        // An 8-byte tombstoned buffer is not a valid `Channel` (length
        // mismatch — Channel::LEN == 216). Direct call to Channel::load_mut
        // is gated; from_account_mut requires an AccountView, so this
        // unit-level check exercises the length gate inside `load_mut`.
        let mut bytes = [0u8; ClosedChannel::LEN];
        ClosedChannel::write_into(&mut bytes).unwrap();
        let err =
            unsafe { crate::state::transmutable::load_mut::<Channel>(&mut bytes) }.unwrap_err();
        assert_eq!(err, ProgramError::InvalidAccountData);
    }
}
