//! Voucher verification.
//!
//! Parses the caller-bundled Ed25519 precompile ix from the Instructions
//! sysvar at `current - 1` (and, for the metered pair, the cap at
//! `current - 2` and the claim at `current - 1`), reads the voucher fields straight out of the
//! precompile-verified message, and checks binding / epoch / freshness / cap
//! / strict monotonicity / precompile pubkey against the channel state. The
//! signed message IS the Borsh voucher payload, so there is no second on-wire
//! copy to carry or reconcile. Pure validator; the caller is responsible for
//! writing [`Channel::settled`] back.
//!
//! Precompile wire layout + parser live in the sibling [`super::ed25519`]
//! module.

use pinocchio::{
    AccountView, Address,
    error::ProgramError,
    sysvars::instructions::{Instructions, IntrospectedInstruction},
};

use super::ed25519::parse as ed25519_ix;
use crate::errors::PaymentChannelsError;
use crate::instructions::{
    CAP_VOUCHER_MAGIC, CAP_VOUCHER_PAYLOAD_SIZE, CLAIM_VOUCHER_MAGIC, CLAIM_VOUCHER_PAYLOAD_SIZE,
    CapVoucherArgs, ClaimVoucherArgs, VOUCHER_MAGIC, VOUCHER_PAYLOAD_SIZE, VoucherArgs,
};
use crate::state::channel::Channel;
use crate::state::{Transmutable, load};

/// Verify a voucher against the channel and the preceding Ed25519 ix.
/// Returns the new watermark on success.
pub fn verify_voucher(
    channel_address: &Address,
    channel: &Channel,
    instructions_sysvar: &AccountView,
    now_unix: i64,
) -> Result<u64, ProgramError> {
    let sysvar = Instructions::try_from(instructions_sysvar)?;
    let current = sysvar.load_current_index();
    let prev_idx = current
        .checked_sub(1)
        .ok_or(PaymentChannelsError::MissingEd25519Verification)?;
    let ix = sysvar
        .load_instruction_at(prev_idx as usize)
        .map_err(|_| PaymentChannelsError::MissingEd25519Verification)?;
    if ix.get_program_id() != &crate::ed25519::PROGRAM_ID {
        return Err(PaymentChannelsError::MissingEd25519Verification.into());
    }
    let parsed = ed25519_ix::parse(ix.get_instruction_data(), VOUCHER_PAYLOAD_SIZE)
        .map_err(|_| PaymentChannelsError::MalformedEd25519Instruction)?;
    verify_parsed(channel_address, channel, &parsed, now_unix)
}

/// Verify the metered cap/claim pair against the channel. Returns the new
/// watermark (the claim) on success.
///
/// The two Ed25519 ixs immediately before this instruction must hold the cap
/// at `current - 2` and the claim at `current - 1`; a slot whose magic is not
/// the expected kind fails with `VoucherBadMagic` before the next slot loads.
/// Cap: signed by [`Channel::authorized_signer`], names the operator allowed
/// to claim under it. Claim: signed by that operator. Both must be bound to
/// this channel and fresh, and `settled < claim <= cap <= deposit`.
pub fn verify_metered_pair(
    channel_address: &Address,
    channel: &Channel,
    instructions_sysvar: &AccountView,
    now_unix: i64,
) -> Result<u64, ProgramError> {
    let sysvar = Instructions::try_from(instructions_sysvar)?;
    let current = sysvar.load_current_index();

    let cap_ix = load_ed25519_ix(
        &sysvar,
        current,
        2,
        PaymentChannelsError::MissingSecondEd25519Verification,
    )?;
    let cap_parsed = parse_metered(&cap_ix, CAP_VOUCHER_MAGIC)?;
    let claim_ix = load_ed25519_ix(
        &sysvar,
        current,
        1,
        PaymentChannelsError::MissingEd25519Verification,
    )?;
    let claim_parsed = parse_metered(&claim_ix, CLAIM_VOUCHER_MAGIC)?;

    // The parser pinned each message to its exact payload size, and both
    // structs are align-1, so these zero-copy loads cannot fail.
    let cap: &CapVoucherArgs = read_pinned(cap_parsed.message)?;
    let claim: &ClaimVoucherArgs = read_pinned(claim_parsed.message)?;

    check_binding(&cap.channel_id, channel_address, cap.expires_at(), now_unix)?;
    let authorized: Address = channel.authorized_signer;
    if cap_parsed.pubkey != authorized.as_array() {
        return Err(PaymentChannelsError::VoucherSignerMismatch.into());
    }

    check_binding(
        &claim.channel_id,
        channel_address,
        claim.expires_at(),
        now_unix,
    )?;
    if claim_parsed.pubkey != cap.operator.as_array() {
        return Err(PaymentChannelsError::VoucherOperatorMismatch.into());
    }

    let cap_cumulative = cap.cap_cumulative();
    if cap_cumulative > channel.deposit() {
        return Err(PaymentChannelsError::VoucherOverDeposit.into());
    }

    let claim_cumulative = claim.claim_cumulative();
    if claim_cumulative > cap_cumulative {
        return Err(PaymentChannelsError::ClaimExceedsCap.into());
    }

    if channel.settled() >= claim_cumulative {
        return Err(PaymentChannelsError::VoucherWatermarkNotMonotonic.into());
    }

    Ok(claim_cumulative)
}

/// Zero-copy load of a payload whose length the Ed25519 parser already pinned.
///
/// `load` only fails when `bytes.len()` is not `T::LEN`. [`parse_metered`]
/// guarantees that for both voucher kinds; the error stays so a length bug
/// rejects the instruction instead of reading off the end of the message.
fn read_pinned<T: Transmutable>(bytes: &[u8]) -> Result<&T, ProgramError> {
    unsafe { load::<T>(bytes) }
        .map_err(|_| PaymentChannelsError::MalformedEd25519Instruction.into())
}

/// Load `ix[current - distance]` and require it to be the Ed25519 precompile;
/// `missing` is returned when the slot is absent or holds another program.
fn load_ed25519_ix<'s>(
    sysvar: &'s Instructions<impl core::ops::Deref<Target = [u8]>>,
    current: u16,
    distance: u16,
    missing: PaymentChannelsError,
) -> Result<IntrospectedInstruction<'s>, ProgramError> {
    let index = current.checked_sub(distance).ok_or(missing)?;
    let ix = sysvar
        .load_instruction_at(index as usize)
        .map_err(|_| missing)?;
    if ix.get_program_id() != &crate::ed25519::PROGRAM_ID {
        return Err(missing.into());
    }
    Ok(ix)
}

/// Parse a metered precompile ix. The message size picks the expected kind,
/// cap (82 bytes) or claim (50 bytes); the canonical layout is validated
/// before any message byte is read, then the magic must match that kind and
/// the kind must be the one `slot_magic` expects at this position.
fn parse_metered<'i>(
    ix: &'i IntrospectedInstruction<'_>,
    slot_magic: [u8; 2],
) -> Result<ed25519_ix::Parsed<'i>, ProgramError> {
    let data = ix.get_instruction_data();
    let (message_len, expected_magic) = match data.len().checked_sub(super::ed25519::MESSAGE_OFFSET)
    {
        Some(CAP_VOUCHER_PAYLOAD_SIZE) => (CAP_VOUCHER_PAYLOAD_SIZE, CAP_VOUCHER_MAGIC),
        Some(CLAIM_VOUCHER_PAYLOAD_SIZE) => (CLAIM_VOUCHER_PAYLOAD_SIZE, CLAIM_VOUCHER_MAGIC),
        _ => return Err(PaymentChannelsError::MalformedEd25519Instruction.into()),
    };
    let parsed = ed25519_ix::parse(data, message_len)
        .map_err(|_| PaymentChannelsError::MalformedEd25519Instruction)?;
    if parsed.message[..2] != expected_magic || expected_magic != slot_magic {
        return Err(PaymentChannelsError::VoucherBadMagic.into());
    }
    Ok(parsed)
}

/// Channel binding and freshness (`expires_at == 0` means no expiry) for the
/// metered cap and claim; [`parse_metered`] has already pinned the magic.
///
/// Mirrors the inline checks in [`verify_parsed`], which stay inline because
/// the v1 path is audited. A change to either copy must be made in both.
fn check_binding(
    channel_id: &Address,
    channel_address: &Address,
    expires_at: i64,
    now_unix: i64,
) -> Result<(), ProgramError> {
    // Address binding IS the epoch binding: `open_slot` is a PDA seed, so
    // an address never hosts two incarnations (see
    // `constants::OPEN_SLOT_WINDOW`) and a voucher issued for a previous
    // channel at recycled parameters targets an address that no longer —
    // and can never again — exist.
    if channel_id != channel_address {
        return Err(PaymentChannelsError::VoucherChannelMismatch.into());
    }

    if expires_at != 0 && now_unix >= expires_at {
        return Err(PaymentChannelsError::VoucherExpired.into());
    }

    Ok(())
}

/// Validate the precompile-verified voucher against channel state.
///
/// The Ed25519 precompile has already proven that `parsed.message` was signed
/// by `parsed.pubkey`. That message *is* the Borsh voucher payload
/// (`magic || channel_id || cumulative_amount || expires_at`), so
/// the voucher fields are read directly from it — there is no caller-supplied
/// copy, hence no message-equality check to perform.
fn verify_parsed(
    channel_address: &Address,
    channel: &Channel,
    parsed: &ed25519_ix::Parsed<'_>,
    now_unix: i64,
) -> Result<u64, ProgramError> {
    // `ed25519_ix::parse` pinned the message to `VOUCHER_PAYLOAD_SIZE` at the
    // canonical offset, so `parsed.message` is exactly a `VoucherArgs`
    // bit-pattern. `VoucherArgs` is align-1, so this zero-copy load cannot
    // fail on length or alignment (the map_err is unreachable in practice).
    let voucher: &VoucherArgs = unsafe { load::<VoucherArgs>(parsed.message) }
        .map_err(|_| PaymentChannelsError::MalformedEd25519Instruction)?;

    if voucher.magic != VOUCHER_MAGIC {
        return Err(PaymentChannelsError::VoucherBadMagic.into());
    }

    // Address binding IS the epoch binding: `open_slot` is a PDA seed, so
    // an address never hosts two incarnations (see
    // `constants::OPEN_SLOT_WINDOW`) and a voucher issued for a previous
    // channel at recycled parameters targets an address that no longer —
    // and can never again — exist.
    if voucher.channel_id != *channel_address {
        return Err(PaymentChannelsError::VoucherChannelMismatch.into());
    }

    let expires_at: i64 = voucher.expires_at();
    if expires_at != 0 && now_unix >= expires_at {
        return Err(PaymentChannelsError::VoucherExpired.into());
    }

    let cumulative: u64 = voucher.cumulative_amount();
    let deposit: u64 = channel.deposit();
    if cumulative > deposit {
        return Err(PaymentChannelsError::VoucherOverDeposit.into());
    }

    let settled: u64 = channel.settled();
    if settled >= cumulative {
        return Err(PaymentChannelsError::VoucherWatermarkNotMonotonic.into());
    }

    let authorized: Address = channel.authorized_signer;
    if parsed.pubkey != authorized.as_array() {
        return Err(PaymentChannelsError::VoucherSignerMismatch.into());
    }

    Ok(cumulative)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use crate::state::Transmutable;

    const CHANNEL_ID: Address = Address::new_from_array([7u8; 32]);
    /// Channel authorized signer.
    const AUTH: Address = Address::new_from_array([66u8; 32]);
    /// Other pubkey for wrong-pubkey tests.
    const OTHER_PUBKEY: Address = Address::new_from_array([85u8; 32]);
    /// Fill bytes for the 64-byte signature region of the synthetic
    /// precompile ix. Never read by the verifier; kept distinctive so
    /// accidental mis-slices show up in test failures.
    const AUTH_SIGNATURE: [u8; 64] = [154u8; 64];

    /// Build a [`Channel`] for fixtures: only the fields the voucher
    /// path reads (`settled`, `deposit`, `authorized_signer`) are set;
    /// everything else is zero.
    fn make_channel(settled: u64, deposit: u64, authorized_signer: Address) -> Channel {
        let mut ch: Channel = unsafe { core::mem::zeroed() };
        ch.set_deposit(deposit);
        ch.set_settled(settled);
        ch.authorized_signer = authorized_signer;
        ch
    }

    /// Encode an Ed25519 precompile ix in the canonical single-signature
    /// layout: `[num_sigs=1, pad=0, offsets×1, pubkey, signature, message]`.
    /// All three `*_instruction_index` fields are set to `u16::MAX` so
    /// `parse` accepts the output by default; tests that exercise guard
    /// failures tamper specific bytes of the returned buffer afterwards.
    fn build_ix_data(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Vec<u8> {
        use crate::ed25519::{
            MESSAGE_OFFSET, PUBKEY_OFFSET, PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSET,
            SIGNATURE_SERIALIZED_SIZE,
        };

        let mut data = Vec::with_capacity(MESSAGE_OFFSET + message.len());
        data.push(1u8); // num_sigs
        data.push(0u8); // padding

        let pubkey_offset = PUBKEY_OFFSET as u16;
        let signature_offset = SIGNATURE_OFFSET as u16;
        let message_offset = MESSAGE_OFFSET as u16;
        let message_size = message.len() as u16;

        data.extend_from_slice(&signature_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // signature_instruction_index
        data.extend_from_slice(&pubkey_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // pubkey_instruction_index
        data.extend_from_slice(&message_offset.to_le_bytes());
        data.extend_from_slice(&message_size.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // message_instruction_index

        debug_assert_eq!(pubkey.len(), PUBKEY_SERIALIZED_SIZE);
        debug_assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);
        data.extend_from_slice(pubkey);
        data.extend_from_slice(signature);
        data.extend_from_slice(message);
        data
    }

    /// Assert `result` is an error whose `ProgramError::Custom` code
    /// equals the numeric discriminant of `expected`. Panics on `Ok`
    /// or on a non-custom error — used by every `verify_parsed` test
    /// that pins a specific validator failure.
    fn expect_err<T>(result: Result<T, ProgramError>, expected: PaymentChannelsError) {
        match result {
            Ok(_) => panic!("expected error, got Ok"),
            Err(ProgramError::Custom(c)) => assert_eq!(c, expected as u32),
            Err(e) => panic!("expected custom error, got {:?}", e),
        }
    }

    /// Construct a [`ed25519_ix::Parsed`] for a canonical precompile ix signed
    /// by [`AUTH`]. Lets `verify_parsed`-only tests skip both the parse pipeline
    /// and the sysvar plumbing that `verify_voucher` would run.
    fn valid_parsed(message: &[u8]) -> ed25519_ix::Parsed<'_> {
        ed25519_ix::Parsed {
            pubkey: AUTH.as_array(),
            message,
        }
    }

    // --- payload contract -------------------------------------------------

    /// Pins the `magic || channel_id || cumulative_amount ||
    /// expires_at` byte layout that the off-chain signer and the Ed25519
    /// precompile depend on. `as_bytes` is a zero-cost reinterpretation of
    /// the struct, so this doubles as a guard against anyone reordering
    /// [`VoucherArgs`] without updating the signer contract.
    #[test]
    fn voucher_args_bytes_match_signed_payload_layout() {
        const CUMULATIVE: u64 = u64::from_le_bytes([119, 102, 85, 68, 51, 34, 17, 0]);
        const EXPIRES_AT: i64 = i64::from_le_bytes([248, 249, 250, 251, 252, 253, 254, 127]);
        let args = VoucherArgs::new(CHANNEL_ID, CUMULATIVE, EXPIRES_AT);
        let bytes = args.as_bytes();
        assert_eq!(bytes.len(), VOUCHER_PAYLOAD_SIZE);
        assert_eq!(&bytes[..2], &VOUCHER_MAGIC);
        assert_eq!(&bytes[..2], &[0x56, 0x01]);
        assert_eq!(&bytes[2..34], CHANNEL_ID.as_array());
        assert_eq!(&bytes[34..42], &CUMULATIVE.to_le_bytes());
        assert_eq!(&bytes[42..50], &EXPIRES_AT.to_le_bytes());
    }

    // --- happy paths ------------------------------------------------------

    #[test]
    fn ok_strict_monotonic_no_expiry() {
        let ch = make_channel(100, 1_000, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 200, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        let out = verify_parsed(&CHANNEL_ID, &ch, &parsed, 1_000_000).unwrap();
        assert_eq!(out, 200);
    }

    #[test]
    fn ok_expiry_in_future() {
        let ch = make_channel(100, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 500, 2_000);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        let out = verify_parsed(&CHANNEL_ID, &ch, &parsed, 1_999).unwrap();
        assert_eq!(out, 500);
    }

    // --- magic / epoch binding -------------------------------------------

    #[test]
    fn wrong_magic() {
        let ch = make_channel(0, 500, AUTH);
        let mut v = VoucherArgs::new(CHANNEL_ID, 100, 0);
        v.magic[1] = 0x02; // wrong format version byte
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherBadMagic,
        );
    }

    #[test]
    fn zeroed_magic() {
        let ch = make_channel(0, 500, AUTH);
        let mut v = VoucherArgs::new(CHANNEL_ID, 100, 0);
        v.magic = [0u8; 2];
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherBadMagic,
        );
    }

    // --- binding / freshness / monotonicity / cap ------------------------

    #[test]
    fn wrong_channel_id() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(Address::new_from_array([9u8; 32]), 100, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherChannelMismatch,
        );
    }

    #[test]
    fn now_equals_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 500);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 500),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn now_past_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 500);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 501),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn negative_expires_at_fails_closed() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, -1);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn cumulative_equals_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 250, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_below_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_zero_on_fresh_channel() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 0, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_above_deposit() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 501, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherOverDeposit,
        );
    }

    // --- Ed25519 structural failures (ed25519_ix::parse) -----------------

    /// Run `parse` and unwrap the expected error. Panics if parsing
    /// unexpectedly succeeds — structural-failure tests always pass
    /// deliberately malformed data.
    fn parse_err(data: &[u8]) -> ed25519_ix::Ed25519ParseError {
        ed25519_ix::parse(data, VOUCHER_PAYLOAD_SIZE)
            .err()
            .expect("parse should fail")
    }

    #[test]
    fn num_signatures_zero() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data[0] = 0;
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::NumSignatures
        );
    }

    #[test]
    fn num_signatures_two() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data[0] = 2;
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::NumSignatures
        );
    }

    #[test]
    fn signature_offset_non_canonical() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        // signature_offset sits at offsets[0..2] → data[2..4]
        data[2..4].copy_from_slice(&49u16.to_le_bytes());
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::NonCanonicalOffsets,
        );
    }

    #[test]
    fn public_key_offset_non_canonical() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        // public_key_offset sits at offsets[4..6] → data[6..8]
        data[6..8].copy_from_slice(&17u16.to_le_bytes());
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::NonCanonicalOffsets,
        );
    }

    #[test]
    fn message_data_offset_non_canonical() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        // message_data_offset sits at offsets[8..10] → data[10..12]
        data[10..12].copy_from_slice(&113u16.to_le_bytes());
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::NonCanonicalOffsets,
        );
    }

    #[test]
    fn message_data_size_above_canonical_50() {
        // Canonical 162-byte ix, but overwrite the declared
        // `message_data_size` field at offsets[10..12] (= data[12..14])
        // to 51. Length guard passes; the dedicated size-check fires.
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data[12..14].copy_from_slice(&51u16.to_le_bytes());
        assert_eq!(parse_err(&data), ed25519_ix::Ed25519ParseError::MessageSize);
    }

    #[test]
    fn message_data_size_below_canonical_50() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data[12..14].copy_from_slice(&49u16.to_le_bytes());
        assert_eq!(parse_err(&data), ed25519_ix::Ed25519ParseError::MessageSize);
    }

    #[test]
    fn ix_data_shorter_than_canonical() {
        // 161 bytes — one shy of the canonical 162-byte layout. Must
        // fail fast before any offsets are read, so short ixs return a
        // clean error instead of panicking on out-of-bounds indexing.
        let short = [0u8; 161];
        assert_eq!(parse_err(&short), ed25519_ix::Ed25519ParseError::Length);
    }

    #[test]
    fn ix_data_longer_than_canonical() {
        // 163 bytes — trailing byte past the pinned layout.
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data.push(0u8);
        assert_eq!(parse_err(&data), ed25519_ix::Ed25519ParseError::Length);
    }

    #[test]
    fn non_zero_padding_rejects() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data[1] = 1;
        assert_eq!(parse_err(&data), ed25519_ix::Ed25519ParseError::Padding);
    }

    #[test]
    fn signature_instruction_index_not_u16_max() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        // offsets[2..4] is signature_instruction_index
        data[4] = 0;
        data[5] = 0;
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::CrossInstruction,
        );
    }

    #[test]
    fn public_key_instruction_index_not_u16_max() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        // offsets[6..8] is pubkey_instruction_index
        data[8] = 0;
        data[9] = 0;
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::CrossInstruction,
        );
    }

    #[test]
    fn parse_accepts_cap_sized_message() {
        let message = [0x56u8, 0x03].repeat(CAP_VOUCHER_PAYLOAD_SIZE / 2);
        let data = build_ix_data(AUTH.as_array(), &message, &AUTH_SIGNATURE);
        let parsed =
            ed25519_ix::parse(&data, CAP_VOUCHER_PAYLOAD_SIZE).expect("82-byte canonical message");
        assert_eq!(parsed.message, message.as_slice());
        assert_eq!(parse_err(&data), ed25519_ix::Ed25519ParseError::Length);
    }

    fn cap_ix_data() -> Vec<u8> {
        build_ix_data(
            AUTH.as_array(),
            &[0u8; CAP_VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        )
    }

    fn parse_cap_err(data: &[u8]) -> ed25519_ix::Ed25519ParseError {
        ed25519_ix::parse(data, CAP_VOUCHER_PAYLOAD_SIZE)
            .err()
            .expect("parse should fail")
    }

    #[test]
    fn cap_message_data_size_not_82() {
        for declared in [81u16, 83] {
            let mut data = cap_ix_data();
            data[12..14].copy_from_slice(&declared.to_le_bytes());
            assert_eq!(
                parse_cap_err(&data),
                ed25519_ix::Ed25519ParseError::MessageSize
            );
        }
    }

    #[test]
    fn cap_ix_data_with_rider_byte() {
        let mut data = cap_ix_data();
        data.push(0u8);
        assert_eq!(parse_cap_err(&data), ed25519_ix::Ed25519ParseError::Length);
    }

    #[test]
    fn cap_instruction_indexes_not_u16_max() {
        // signature, public key and message `*_instruction_index` fields.
        for at in [4usize, 8, 14] {
            let mut data = cap_ix_data();
            data[at..at + 2].copy_from_slice(&0u16.to_le_bytes());
            assert_eq!(
                parse_cap_err(&data),
                ed25519_ix::Ed25519ParseError::CrossInstruction,
            );
        }
    }

    #[test]
    fn message_instruction_index_not_u16_max() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        // offsets[12..14] is message_instruction_index
        data[14] = 0;
        data[15] = 0;
        assert_eq!(
            parse_err(&data),
            ed25519_ix::Ed25519ParseError::CrossInstruction,
        );
    }

    // --- Ed25519 content failures ----------------------------------------

    // The former `message_off_by_one_byte` test was removed alongside the
    // message-equality check: the voucher is now read straight from the
    // precompile-verified message, so there is no caller-supplied copy to
    // diverge from it. A tampered message either fails the Ed25519 signature
    // check in the precompile itself, or — when a field byte is altered —
    // trips the magic / channel / epoch / expiry / cap / monotonic guards
    // exercised above (e.g. flipping a `channel_id` byte yields
    // `VoucherChannelMismatch`).

    #[test]
    fn precompile_pubkey_not_authorized_signer() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 0);
        let msg = v.as_bytes();
        let parsed = ed25519_ix::Parsed {
            pubkey: OTHER_PUBKEY.as_array(),
            message: msg,
        };
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &parsed, 0),
            PaymentChannelsError::VoucherSignerMismatch,
        );
    }

    // --- defensive branches ----------------------------------------------
    //
    // A real Instructions sysvar always has `current < num_instructions`, and
    // `verify_metered_pair` only asks for `current - 1` after `current - 2`
    // already resolved, so these returns are unreachable on chain. The
    // helpers still define them, and a hand-built sysvar reaches them.

    /// Instructions-sysvar bytes: `num_instructions`, one unused offset, then
    /// the current index in the trailing two bytes.
    fn sysvar_bytes(num_instructions: u16, current: u16) -> [u8; 6] {
        let mut data = [0u8; 6];
        data[..2].copy_from_slice(&num_instructions.to_le_bytes());
        data[4..].copy_from_slice(&current.to_le_bytes());
        data
    }

    /// `current - 2` is in range of the subtraction but past `num_instructions`,
    /// so `load_instruction_at` rejects it.
    #[test]
    fn load_rejects_an_index_past_num_instructions() {
        let data = sysvar_bytes(1, 3);
        let sysvar = unsafe { Instructions::new_unchecked(&data[..]) };
        expect_err(
            load_ed25519_ix(
                &sysvar,
                3,
                2,
                PaymentChannelsError::MissingSecondEd25519Verification,
            ),
            PaymentChannelsError::MissingSecondEd25519Verification,
        );
    }

    /// `current - 1` underflows. `verify_metered_pair` cannot get here: its
    /// `current - 2` load runs first and returns on the same `current`.
    #[test]
    fn load_rejects_distance_one_when_current_is_zero() {
        let data = sysvar_bytes(0, 0);
        let sysvar = unsafe { Instructions::new_unchecked(&data[..]) };
        expect_err(
            load_ed25519_ix(
                &sysvar,
                0,
                1,
                PaymentChannelsError::MissingEd25519Verification,
            ),
            PaymentChannelsError::MissingEd25519Verification,
        );
    }

    /// `read_pinned` is the `map_err` on both voucher loads. The parser never
    /// hands it a slice of the wrong length; this pins the error it returns.
    #[test]
    fn pinned_load_rejects_a_slice_of_the_wrong_length() {
        let bytes = [0u8; 1];
        expect_err(
            read_pinned::<CapVoucherArgs>(&bytes).map(|_| ()),
            PaymentChannelsError::MalformedEd25519Instruction,
        );
        expect_err(
            read_pinned::<ClaimVoucherArgs>(&bytes).map(|_| ()),
            PaymentChannelsError::MalformedEd25519Instruction,
        );
    }
}
