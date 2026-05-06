#[cfg(feature = "idl")]
use codama::CodamaAccount;
use core::mem::size_of;
use pinocchio::error::ProgramError;

use crate::state::{
    common::AccountDiscriminator,
    transmutable::{Transmutable, load_mut},
};

/// Tombstoned channel PDA. Replaces the [`Channel`](crate::Channel) bytes via
/// in-place realloc at `distribute`'s FINALIZED branch so the address stays
/// alive forever, owned by the program. Re-init at the same seeds is rejected
/// by the system program (`CreateAccount` requires `lamports == 0`,
/// `Allocate` requires empty data + system ownership). The distinct
/// `AccountDiscriminator::ClosedChannel` is defense-in-depth: any reader
/// going through `Channel::from_account_mut` rejects on the discriminator
/// gate before any status check runs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaAccount))]
pub struct ClosedChannel {
    /// [`AccountDiscriminator::ClosedChannel`]. Callers
    /// cannot construct a `ClosedChannel` with any other byte value; the
    /// only way to produce a valid tombstone is via [`Self::write_into`],
    /// which always writes the canonical discriminator.
    discriminator: u8,
}

impl ClosedChannel {
    pub const LEN: usize = size_of::<Self>();

    /// Overwrite `bytes` with the 1-byte tombstone payload. Caller is
    /// responsible for shrinking the account to [`Self::LEN`] before calling.
    pub fn write_into(bytes: &mut [u8]) -> Result<(), ProgramError> {
        // SAFETY: `ClosedChannel` is `repr(C)` with alignment 1; load_mut
        // checks length and align is verified at every load_mut call site.
        let cc = unsafe { load_mut::<Self>(bytes) }?;
        cc.discriminator = AccountDiscriminator::ClosedChannel as u8;
        Ok(())
    }
}

unsafe impl Transmutable for ClosedChannel {
    const LEN: usize = size_of::<Self>();
}

const _: () = {
    assert!(ClosedChannel::LEN == 1);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::channel::Channel;

    #[test]
    fn len_is_one_byte() {
        assert_eq!(ClosedChannel::LEN, 1);
        assert_eq!(core::mem::size_of::<ClosedChannel>(), 1);
    }

    #[test]
    fn write_into_produces_expected_bytes() {
        let mut bytes = [0u8; ClosedChannel::LEN];
        ClosedChannel::write_into(&mut bytes).unwrap();
        assert_eq!(bytes, [2]);
    }

    #[test]
    fn channel_load_rejects_tombstone_buffer() {
        // A 1-byte tombstoned buffer is not a valid `Channel` (length
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
