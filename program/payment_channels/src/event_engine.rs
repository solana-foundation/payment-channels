//! Event emission via Anchor-compatible self-CPI.
//!
//! Events are emitted by invoking this program's own [`EmitEvent`](crate::instructions::emit_event)
//! instruction via CPI, signed by the compile-time-derived event authority
//! PDA. Indexers detect these inner instructions by the 8-byte
//! [`EVENT_IX_TAG`] prefix in the instruction data.
//!
//! Wire format per event: `tag (8 bytes) | event_disc (8 bytes) | borsh_payload`.
//! The event discriminator is `sha256("event:{StructName}")[..8]` — the same
//! derivation stock `@coral-xyz/anchor`'s `EventParser` uses — so published
//! events round-trip through any Anchor client without custom decoders.
//!
//! Event structs use Borsh, but only its stack-only subset: primitives
//! and fixed-size arrays of primitives (e.g. `[u8; 32]` for pubkeys).
//! Heap-backed types (`Vec`, `String`, `Option<T>`) panic under
//! Pinocchio's `no_allocator!()`.

use borsh::BorshSerialize;
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

/// Wire format prefix length: 8-byte tag + 8-byte sha256 event discriminator.
pub const EVENT_DISCRIMINATOR_LEN: usize = 8 + 8;

/// Instruction discriminator for the EmitEvent no-op instruction.
///
/// Equal to `EVENT_IX_TAG_LE[0]` so that self-CPI event bytes
/// (`tag | event_disc | payload`) route to `emit_event::process` via
/// the program's byte-0 dispatch.
pub const EMIT_EVENT_IX_DISC: u8 = 228;

/// Compile-time derived PDA for the event authority.
pub mod event_authority_pda {
    use super::*;

    const EVENT_AUTHORITY_AND_BUMP: ([u8; 32], u8) =
        ed25519::derive_program_address(&[EVENT_AUTHORITY_SEED], crate::ID.as_array());

    pub const ID: Address = Address::new_from_array(EVENT_AUTHORITY_AND_BUMP.0);
    pub const BUMP: u8 = EVENT_AUTHORITY_AND_BUMP.1;
}

/// Derive the 8-byte Anchor event discriminator at compile time.
///
/// Mirrors Anchor's `sha256("event:{StructName}")[..8]` derivation so
/// events are readable by stock `@coral-xyz/anchor` indexers.
#[macro_export]
macro_rules! anchor_event_disc {
    ($name:literal) => {{
        const H: [u8; 32] = ::const_crypto::sha2::Sha256::new()
            .update(concat!("event:", $name).as_bytes())
            .finalize();
        [H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]]
    }};
}

/// Fixed-capacity stack buffer used as the event wire-format writer.
/// Sized per event type via `EventSerialize::WIRE_LEN`.
pub struct EventBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> EventBuf<N> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    /// Append `src` to the buffer. Debug-asserts capacity; release builds
    /// rely on `WIRE_LEN` being const-computed correctly per event.
    pub fn write(&mut self, src: &[u8]) {
        debug_assert!(self.len + src.len() <= N);
        self.bytes[self.len..self.len + src.len()].copy_from_slice(src);
        self.len += src.len();
    }

    pub fn push(&mut self, b: u8) {
        debug_assert!(self.len < N);
        self.bytes[self.len] = b;
        self.len += 1;
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const N: usize> Default for EventBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Route `BorshSerialize::serialize` output into an `EventBuf`. The buffer
/// is sized at the call site to `WIRE_LEN`, so writes never exceed
/// capacity in correctly-typed code; debug_assert catches regressions.
impl<const N: usize> borsh::io::Write for EventBuf<N> {
    fn write(&mut self, buf: &[u8]) -> borsh::io::Result<usize> {
        <EventBuf<N>>::write(self, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> borsh::io::Result<()> {
        Ok(())
    }
}

/// Identifies which event type this struct represents. The 8-byte
/// discriminator is Anchor's `sha256("event:{StructName}")[..8]`.
pub trait EventDiscriminator {
    const DISCRIMINATOR: [u8; 8];
}

/// Serializes an event into its wire format: tag + 8-byte discriminator
/// + Borsh-encoded field data.
pub trait EventSerialize: EventDiscriminator + BorshSerialize + Sized {
    /// Size of the Borsh-encoded payload alone (no tag, no discriminator).
    /// Declared per-event so `to_bytes_fixed::<{ E::WIRE_LEN }>()` can be
    /// used at call sites. A unit test cross-checks this against
    /// `borsh::object_length` at runtime.
    const DATA_LEN: usize;

    /// Full framing: 8-byte tag + 8-byte event discriminator + `DATA_LEN`.
    const WIRE_LEN: usize = Self::DATA_LEN + EVENT_DISCRIMINATOR_LEN;

    /// Build the on-wire representation into a stack buffer of exactly
    /// `Self::WIRE_LEN` bytes.
    ///
    /// Call sites: `MyEvent { .. }.to_bytes_fixed::<{ MyEvent::WIRE_LEN }>()`.
    fn to_bytes_fixed<const N: usize>(&self) -> EventBuf<N> {
        let mut buf = EventBuf::<N>::new();
        buf.write(&EVENT_IX_TAG_LE);
        buf.write(&Self::DISCRIMINATOR);
        self.serialize(&mut buf)
            .expect("EventBuf sized to WIRE_LEN");
        buf
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

    invoke_signed::<2, _>(&instruction, &[event_authority, self_program], &[signer])
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};

    #[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
    struct StubEvent {
        value: u64,
    }

    impl EventDiscriminator for StubEvent {
        const DISCRIMINATOR: [u8; 8] = crate::anchor_event_disc!("StubEvent");
    }

    impl EventSerialize for StubEvent {
        const DATA_LEN: usize = 8;
    }

    #[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
    struct StubPubkeyEvent {
        who: [u8; 32],
    }

    impl EventDiscriminator for StubPubkeyEvent {
        const DISCRIMINATOR: [u8; 8] = crate::anchor_event_disc!("StubPubkeyEvent");
    }

    impl EventSerialize for StubPubkeyEvent {
        const DATA_LEN: usize = 32;
    }

    /// sha256("event:StubEvent")[..8]. Baked as a literal (vs. recomputed
    /// via the macro in the test) so the golden breaks loudly if either
    /// the macro's hashing or the event name drifts.
    const STUB_EVENT_DISC_EXPECTED: [u8; 8] = [0x7d, 0xb7, 0x3e, 0xdc, 0x42, 0x0e, 0xa2, 0x13];

    #[test]
    fn tag_first_byte_equals_emit_event_disc() {
        // Dispatch invariant: self-CPI event bytes start with the tag,
        // whose first byte must equal the emit_event instruction
        // discriminator so the program's byte-0 dispatcher routes to it.
        assert_eq!(EVENT_IX_TAG_LE[0], EMIT_EVENT_IX_DISC);
    }

    #[test]
    fn constants_are_consistent() {
        assert_eq!(EVENT_IX_TAG_LE, EVENT_IX_TAG.to_le_bytes());
        assert_eq!(EVENT_DISCRIMINATOR_LEN, 8 + 8);
    }

    #[test]
    fn wire_len_is_tag_plus_disc_plus_data() {
        assert_eq!(StubEvent::WIRE_LEN, EVENT_DISCRIMINATOR_LEN + 8);
        assert_eq!(StubPubkeyEvent::WIRE_LEN, EVENT_DISCRIMINATOR_LEN + 32);
    }

    #[test]
    fn wire_format_golden_bytes_for_stub() {
        let event = StubEvent { value: 0xCAFE };
        let buf = event.to_bytes_fixed::<{ StubEvent::WIRE_LEN }>();
        let bytes = buf.as_slice();

        // Exact 24-byte wire image:
        //   [0..8)   tag (EVENT_IX_TAG little-endian)
        //   [8..16)  sha256("event:StubEvent")[..8]
        //   [16..24) value as u64-LE
        let mut expected = [0u8; 24];
        expected[..8].copy_from_slice(&EVENT_IX_TAG_LE);
        expected[8..16].copy_from_slice(&STUB_EVENT_DISC_EXPECTED);
        expected[16..].copy_from_slice(&0xCAFEu64.to_le_bytes());

        assert_eq!(bytes, &expected[..]);
    }

    #[test]
    fn discriminator_is_sha256_of_event_prefix() {
        assert_eq!(StubEvent::DISCRIMINATOR, STUB_EVENT_DISC_EXPECTED);
    }

    #[test]
    fn data_len_matches_borsh_object_length() {
        let a = StubEvent { value: 42 };
        assert_eq!(StubEvent::DATA_LEN, borsh::object_length(&a).unwrap());

        let b = StubPubkeyEvent { who: [7u8; 32] };
        assert_eq!(StubPubkeyEvent::DATA_LEN, borsh::object_length(&b).unwrap());
    }

    #[test]
    fn anchor_event_parser_round_trip() {
        // Simulates what `@coral-xyz/anchor`'s EventParser does:
        // 1. match the 8-byte tag
        // 2. read the 8-byte event discriminator
        // 3. `borsh::from_slice` the remainder into the event struct
        let event = StubEvent { value: 123 };
        let buf = event.to_bytes_fixed::<{ StubEvent::WIRE_LEN }>();
        let bytes = buf.as_slice();

        assert_eq!(&bytes[..8], &EVENT_IX_TAG_LE);
        assert_eq!(&bytes[8..16], &StubEvent::DISCRIMINATOR);

        let decoded: StubEvent = borsh::from_slice(&bytes[16..]).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn event_buf_write_and_push_compose() {
        let mut buf = EventBuf::<8>::new();
        buf.write(&[1, 2, 3]);
        buf.push(4);
        buf.write(&[5, 6]);
        buf.push(7);
        buf.push(8);
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn event_buf_impls_borsh_io_write() {
        let mut buf = EventBuf::<8>::new();
        42u64.serialize(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), &42u64.to_le_bytes());
    }

    #[test]
    fn different_events_produce_different_wire_bytes() {
        let a = StubEvent { value: 1 };
        let b = StubPubkeyEvent { who: [1u8; 32] };
        let buf_a = a.to_bytes_fixed::<{ StubEvent::WIRE_LEN }>();
        let buf_b = b.to_bytes_fixed::<{ StubPubkeyEvent::WIRE_LEN }>();

        assert_ne!(buf_a.as_slice(), buf_b.as_slice());
        assert_ne!(StubEvent::DISCRIMINATOR, StubPubkeyEvent::DISCRIMINATOR);
    }
}
