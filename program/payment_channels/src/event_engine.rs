//! Event emission via Anchor-compatible self-CPI.
//!
//! Events are emitted by invoking this program's own [`EmitEvent`](crate::instructions::emit_event)
//! instruction via CPI, signed by the compile-time-derived event authority
//! PDA. Indexers detect these inner instructions by the 8-byte
//! [`EVENT_IX_TAG`] prefix in the instruction data.

use core::mem::size_of;

extern crate alloc;
use alloc::vec::Vec;

use const_crypto::ed25519;
use pinocchio::cpi::{Seed, Signer, invoke_signed};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::errors::PaymentChannelsError;

/// PDA seed for the event authority account.
pub const EVENT_AUTHORITY_SEED: &[u8] = b"event_authority";

/// Anchor-compatible event tag: `Sha256("anchor:event")[..8]`.
/// Indexers use this prefix to identify CPI event data in inner instructions.
pub const EVENT_IX_TAG: u64 = 0x1d9acb512ea545e4;

/// Little-endian byte representation of [`EVENT_IX_TAG`].
pub const EVENT_IX_TAG_LE: [u8; 8] = EVENT_IX_TAG.to_le_bytes();

/// Wire format prefix length: 8-byte tag + 1-byte event discriminator.
pub const EVENT_DISCRIMINATOR_LEN: usize = size_of::<u64>() + 1;

/// Instruction discriminator for the EmitEvent no-op instruction.
pub const EMIT_EVENT_IX_DISC: u8 = 228;

/// Compile-time derived PDA for the event authority.
pub mod event_authority_pda {
    use super::*;

    const EVENT_AUTHORITY_AND_BUMP: ([u8; 32], u8) =
        ed25519::derive_program_address(&[EVENT_AUTHORITY_SEED], crate::ID.as_array());

    pub const ID: Address = Address::new_from_array(EVENT_AUTHORITY_AND_BUMP.0);
    pub const BUMP: u8 = EVENT_AUTHORITY_AND_BUMP.1;
}

/// Identifies which event type this struct represents.
pub trait EventDiscriminator {
    const DISCRIMINATOR: u8;
}

/// Serializes an event into its wire format: tag + discriminator + field data.
pub trait EventSerialize: EventDiscriminator {
    const DATA_LEN: usize;

    fn write_inner(&self, writer: &mut Vec<u8>);

    fn load(bytes: &[u8]) -> Result<&Self, ProgramError>
    where
        Self: Sized,
    {
        if bytes.len() != Self::DATA_LEN {
            return Err(PaymentChannelsError::InvalidEventData.into());
        }
        Ok(unsafe { &*bytes.as_ptr().cast::<Self>() })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::DATA_LEN + EVENT_DISCRIMINATOR_LEN);
        data.extend_from_slice(&EVENT_IX_TAG_LE);
        data.push(Self::DISCRIMINATOR);
        self.write_inner(&mut data);
        data
    }
}

/// Verifies that the given account matches the compile-time event authority PDA.
#[inline(always)]
pub fn verify_event_authority(account: &AccountView) -> Result<(), ProgramError> {
    if account.address() != &event_authority_pda::ID {
        return Err(PaymentChannelsError::InvalidEventAuthority.into());
    }
    Ok(())
}

/// Emits an event via self-CPI, recording event data in inner instruction data.
pub fn emit_event(
    program_id: &Address,
    event_authority: &AccountView,
    self_program: &AccountView,
    event_data: &[u8],
) -> ProgramResult {
    verify_event_authority(event_authority)?;

    let bump = [event_authority_pda::BUMP];
    let signer_seeds: [Seed; 2] = [Seed::from(EVENT_AUTHORITY_SEED), Seed::from(&bump)];
    let signer = Signer::from(&signer_seeds);

    let accounts = [InstructionAccount::readonly_signer(
        event_authority.address(),
    )];

    let instruction = InstructionView {
        program_id,
        data: event_data,
        accounts: &accounts,
    };

    invoke_signed::<2>(&instruction, &[event_authority, self_program], &[signer])
}

#[cfg(test)]
fn discriminator_bytes<T: EventDiscriminator>() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(EVENT_DISCRIMINATOR_LEN);
    bytes.extend_from_slice(&EVENT_IX_TAG_LE);
    bytes.push(T::DISCRIMINATOR);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubEventA {
        value: u64,
    }
    impl EventDiscriminator for StubEventA {
        const DISCRIMINATOR: u8 = 10;
    }
    impl EventSerialize for StubEventA {
        const DATA_LEN: usize = 8;
        fn write_inner(&self, writer: &mut Vec<u8>) {
            writer.extend_from_slice(&self.value.to_le_bytes());
        }
    }

    struct StubEventB {
        flag: u8,
    }
    impl EventDiscriminator for StubEventB {
        const DISCRIMINATOR: u8 = 20;
    }
    impl EventSerialize for StubEventB {
        const DATA_LEN: usize = 1;
        fn write_inner(&self, writer: &mut Vec<u8>) {
            writer.push(self.flag);
        }
    }

    #[test]
    fn constants_are_consistent() {
        assert_eq!(EVENT_IX_TAG_LE, EVENT_IX_TAG.to_le_bytes());
        assert_eq!(EVENT_DISCRIMINATOR_LEN, 8 + 1);
    }

    #[test]
    fn discriminator_bytes_has_correct_prefix() {
        let disc = discriminator_bytes::<StubEventA>();
        assert_eq!(disc.len(), EVENT_DISCRIMINATOR_LEN);
        assert_eq!(&disc[..8], &EVENT_IX_TAG_LE);
        assert_eq!(disc[8], StubEventA::DISCRIMINATOR);
    }

    #[test]
    fn discriminator_bytes_differ_per_event() {
        let a = discriminator_bytes::<StubEventA>();
        let b = discriminator_bytes::<StubEventB>();
        assert_ne!(a, b);
        assert_eq!(&a[..8], &b[..8]);
        assert_ne!(a[8], b[8]);
    }

    #[test]
    fn to_bytes_prepends_tag_and_discriminator() {
        let event = StubEventA { value: 42 };
        let bytes = event.to_bytes();
        assert_eq!(&bytes[..8], &EVENT_IX_TAG_LE);
        assert_eq!(bytes[8], StubEventA::DISCRIMINATOR);
        assert_eq!(&bytes[9..], &42u64.to_le_bytes());
    }

    #[test]
    fn to_bytes_equals_discriminator_bytes_plus_inner() {
        let event = StubEventA { value: 999 };
        let full = event.to_bytes();
        let mut inner = Vec::new();
        event.write_inner(&mut inner);
        let mut expected = discriminator_bytes::<StubEventA>();
        expected.extend_from_slice(&inner);
        assert_eq!(full, expected);
    }

    #[test]
    fn write_inner_is_only_field_data() {
        let event = StubEventB { flag: 0xFF };
        let mut inner = Vec::new();
        event.write_inner(&mut inner);
        assert_eq!(inner, vec![0xFF]);
    }

    #[test]
    fn different_events_produce_different_wire_bytes() {
        let a = StubEventA { value: 1 };
        let b = StubEventB { flag: 1 };
        assert_ne!(a.to_bytes(), b.to_bytes());
    }
}
