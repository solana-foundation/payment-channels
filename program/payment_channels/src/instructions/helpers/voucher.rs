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
    CAP_VOUCHER_MAGIC, CLAIM_VOUCHER_MAGIC, CapVoucherArgs, ClaimVoucherArgs, VOUCHER_MAGIC,
    VoucherArgs,
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
    let ix = load_ed25519_ix(
        &sysvar,
        current,
        1,
        PaymentChannelsError::MissingEd25519Verification,
    )?;
    let (signer, voucher) = parse_signed::<VoucherArgs>(ix.get_instruction_data(), VOUCHER_MAGIC)?;
    validate_v1_voucher(channel_address, channel, signer, voucher, now_unix)
}

/// Verify the metered cap/claim pair against the channel. Returns the new
/// watermark (the claim) on success.
///
/// The cap rides at `current - 2`, the claim at `current - 1`; each slot is
/// parsed as the type it must hold.
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
    let (cap_signer, cap) =
        parse_signed::<CapVoucherArgs>(cap_ix.get_instruction_data(), CAP_VOUCHER_MAGIC)?;
    let claim_ix = load_ed25519_ix(
        &sysvar,
        current,
        1,
        PaymentChannelsError::MissingEd25519Verification,
    )?;
    let (claim_signer, claim) =
        parse_signed::<ClaimVoucherArgs>(claim_ix.get_instruction_data(), CLAIM_VOUCHER_MAGIC)?;

    validate_channel_and_expiry(&cap.channel_id, channel_address, cap.expires_at(), now_unix)?;
    if cap_signer != channel.authorized_signer.as_array() {
        return Err(PaymentChannelsError::VoucherSignerMismatch.into());
    }

    validate_channel_and_expiry(
        &claim.channel_id,
        channel_address,
        claim.expires_at(),
        now_unix,
    )?;
    if claim_signer != cap.operator.as_array() {
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

/// Parse Ed25519 precompile ix data as a `T`-sized message starting with
/// `magic`. Returns the precompile-verified signer and the typed message.
fn parse_signed<T: Transmutable>(
    data: &[u8],
    magic: [u8; 2],
) -> Result<(&[u8; 32], &T), ProgramError> {
    let parsed = ed25519_ix::parse(data, T::LEN)
        .map_err(|_| PaymentChannelsError::MalformedEd25519Instruction)?;
    if parsed.message[..2] != magic {
        return Err(PaymentChannelsError::VoucherBadMagic.into());
    }
    // SAFETY: `T` is `repr(C)` over byte arrays and `parse` pinned the length.
    let message = unsafe { load::<T>(parsed.message) }
        .map_err(|_| PaymentChannelsError::MalformedEd25519Instruction)?;
    Ok((parsed.pubkey, message))
}

/// Channel binding and freshness (`expires_at == 0` means no expiry), shared
/// by every voucher kind.
fn validate_channel_and_expiry(
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

/// Validate the precompile-verified v1 voucher against channel state.
///
/// The precompile proved `signer` signed the message and [`parse_signed`]
/// pinned its layout and magic; the fields are read straight from it.
fn validate_v1_voucher(
    channel_address: &Address,
    channel: &Channel,
    signer: &[u8; 32],
    voucher: &VoucherArgs,
    now_unix: i64,
) -> Result<u64, ProgramError> {
    validate_channel_and_expiry(
        &voucher.channel_id,
        channel_address,
        voucher.expires_at(),
        now_unix,
    )?;

    let cumulative: u64 = voucher.cumulative_amount();
    let deposit: u64 = channel.deposit();
    if cumulative > deposit {
        return Err(PaymentChannelsError::VoucherOverDeposit.into());
    }

    let settled: u64 = channel.settled();
    if settled >= cumulative {
        return Err(PaymentChannelsError::VoucherWatermarkNotMonotonic.into());
    }

    if signer != channel.authorized_signer.as_array() {
        return Err(PaymentChannelsError::VoucherSignerMismatch.into());
    }

    Ok(cumulative)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use crate::instructions::{CAP_VOUCHER_PAYLOAD_SIZE, VOUCHER_PAYLOAD_SIZE};
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
    /// or on a non-custom error — used by every `validate_v1_voucher` test
    /// that pins a specific validator failure.
    fn expect_err<T>(result: Result<T, ProgramError>, expected: PaymentChannelsError) {
        match result {
            Ok(_) => panic!("expected error, got Ok"),
            Err(ProgramError::Custom(c)) => assert_eq!(c, expected as u32),
            Err(e) => panic!("expected custom error, got {:?}", e),
        }
    }

    /// `verify_voucher` without the sysvar: parse a canonical ix carrying
    /// `message` under `signer`, then verify it.
    fn verify_v1_message(
        ch: &Channel,
        signer: &Address,
        message: &[u8],
        now: i64,
    ) -> Result<u64, ProgramError> {
        let data = build_ix_data(signer.as_array(), message, &AUTH_SIGNATURE);
        let (pubkey, voucher) = parse_signed::<VoucherArgs>(&data, VOUCHER_MAGIC)?;
        validate_v1_voucher(&CHANNEL_ID, ch, pubkey, voucher, now)
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
        let out = verify_v1_message(&ch, &AUTH, msg, 1_000_000).unwrap();
        assert_eq!(out, 200);
    }

    #[test]
    fn ok_expiry_in_future() {
        let ch = make_channel(100, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 500, 2_000);
        let msg = v.as_bytes();
        let out = verify_v1_message(&ch, &AUTH, msg, 1_999).unwrap();
        assert_eq!(out, 500);
    }

    // --- magic / epoch binding -------------------------------------------

    #[test]
    fn wrong_magic() {
        let ch = make_channel(0, 500, AUTH);
        let mut v = VoucherArgs::new(CHANNEL_ID, 100, 0);
        v.magic[1] = 0x02; // wrong format version byte
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
            PaymentChannelsError::VoucherBadMagic,
        );
    }

    #[test]
    fn zeroed_magic() {
        let ch = make_channel(0, 500, AUTH);
        let mut v = VoucherArgs::new(CHANNEL_ID, 100, 0);
        v.magic = [0u8; 2];
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
            PaymentChannelsError::VoucherBadMagic,
        );
    }

    // --- binding / freshness / monotonicity / cap ------------------------

    #[test]
    fn wrong_channel_id() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(Address::new_from_array([9u8; 32]), 100, 0);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
            PaymentChannelsError::VoucherChannelMismatch,
        );
    }

    #[test]
    fn now_equals_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 500);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 500),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn now_past_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 500);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 501),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn negative_expires_at_fails_closed() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, -1);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn cumulative_equals_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 250, 0);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_below_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 0);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_zero_on_fresh_channel() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 0, 0);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_above_deposit() {
        let ch = make_channel(0, 500, AUTH);
        let v = VoucherArgs::new(CHANNEL_ID, 501, 0);
        let msg = v.as_bytes();
        expect_err(
            verify_v1_message(&ch, &AUTH, msg, 0),
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
        expect_err(
            verify_v1_message(&ch, &OTHER_PUBKEY, msg, 0),
            PaymentChannelsError::VoucherSignerMismatch,
        );
    }
}
