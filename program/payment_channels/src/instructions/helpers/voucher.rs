//! Voucher verification.
//!
//! Parses the caller-bundled Ed25519 precompile ix from the Instructions
//! sysvar at `current - 1`, reconstructs the signed payload, and checks
//! binding / freshness / cap / strict monotonicity / message / precompile
//! pubkey against the channel state. Pure validator; the caller is
//! responsible for writing [`Channel::settled`] back.
//!
//! Precompile wire layout + parser live in the sibling [`super::ed25519`]
//! module.

use pinocchio::{AccountView, Address, error::ProgramError, sysvars::instructions::Instructions};

use super::ed25519::parse as ed25519_ix;
use crate::errors::PaymentChannelsError;
use crate::instructions::VoucherArgs;
use crate::state::Transmutable;
use crate::state::channel::Channel;

/// Verify a voucher against the channel and the preceding Ed25519 ix.
/// Returns the new watermark on success.
pub fn verify_voucher(
    channel_address: &Address,
    channel: &Channel,
    voucher: &VoucherArgs,
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
    let parsed = ed25519_ix::parse(ix.get_instruction_data())
        .map_err(|_| PaymentChannelsError::MalformedEd25519Instruction)?;
    verify_parsed(channel_address, channel, voucher, &parsed, now_unix)
}

/// Validate a voucher against channel state and a parsed Ed25519 ix data.
fn verify_parsed(
    channel_address: &Address,
    channel: &Channel,
    voucher: &VoucherArgs,
    parsed: &ed25519_ix::Parsed<'_>,
    now_unix: i64,
) -> Result<u64, ProgramError> {
    let v_channel_id: Address = voucher.channel_id;
    if v_channel_id != *channel_address {
        return Err(PaymentChannelsError::VoucherChannelMismatch.into());
    }

    if voucher.chain_id != crate::CHAIN_ID {
        return Err(PaymentChannelsError::VoucherChainMismatch.into());
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

    if parsed.message != voucher.as_bytes() {
        return Err(PaymentChannelsError::VoucherMessageMismatch.into());
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
    use crate::instructions::VOUCHER_PAYLOAD_SIZE;

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

    /// [`VoucherArgs::new`] carrying this cluster's [`crate::CHAIN_ID`] — every
    /// fixture voucher must bind the local chain or it trips the chain check.
    /// The dedicated `wrong_chain_id` test calls `VoucherArgs::new` directly
    /// with a foreign chain id.
    fn mk_voucher(channel_id: Address, cumulative_amount: u64, expires_at: i64) -> VoucherArgs {
        VoucherArgs::new(channel_id, cumulative_amount, expires_at, crate::CHAIN_ID)
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
    fn expect_err(result: Result<u64, ProgramError>, expected: PaymentChannelsError) {
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
            message: message
                .try_into()
                .expect("test message must be VOUCHER_PAYLOAD_SIZE"),
        }
    }

    // --- payload contract -------------------------------------------------

    /// Pins the `channel_id || cumulative_amount || expires_at || chain_id`
    /// byte layout that the off-chain signer and the Ed25519 precompile
    /// depend on. `as_bytes` is a zero-cost reinterpretation of the
    /// struct, so this doubles as a guard against anyone reordering
    /// [`VoucherArgs`] without updating the signer contract.
    #[test]
    fn voucher_args_bytes_match_signed_payload_layout() {
        const CUMULATIVE: u64 = u64::from_le_bytes([119, 102, 85, 68, 51, 34, 17, 0]);
        const EXPIRES_AT: i64 = i64::from_le_bytes([248, 249, 250, 251, 252, 253, 254, 127]);
        let args = mk_voucher(CHANNEL_ID, CUMULATIVE, EXPIRES_AT);
        let bytes = args.as_bytes();
        assert_eq!(bytes.len(), VOUCHER_PAYLOAD_SIZE);
        assert_eq!(&bytes[..32], CHANNEL_ID.as_array());
        assert_eq!(&bytes[32..40], &CUMULATIVE.to_le_bytes());
        assert_eq!(&bytes[40..48], &EXPIRES_AT.to_le_bytes());
        assert_eq!(&bytes[48..80], crate::CHAIN_ID.as_array());
    }

    // --- happy paths ------------------------------------------------------

    #[test]
    fn ok_strict_monotonic_no_expiry() {
        let ch = make_channel(100, 1_000, AUTH);
        let v = mk_voucher(CHANNEL_ID, 200, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        let out = verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 1_000_000).unwrap();
        assert_eq!(out, 200);
    }

    #[test]
    fn ok_expiry_in_future() {
        let ch = make_channel(100, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 500, 2_000);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        let out = verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 1_999).unwrap();
        assert_eq!(out, 500);
    }

    // --- binding / freshness / monotonicity / cap ------------------------

    #[test]
    fn wrong_channel_id() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(Address::new_from_array([9u8; 32]), 100, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherChannelMismatch,
        );
    }

    #[test]
    fn wrong_chain_id() {
        let ch = make_channel(0, 500, AUTH);
        // Correct channel binding, but a foreign chain id (another cluster's
        // genesis hash) — a cross-cluster replay attempt.
        let foreign_chain = Address::new_from_array([0x42u8; 32]);
        assert_ne!(foreign_chain, crate::CHAIN_ID);
        let v = VoucherArgs::new(CHANNEL_ID, 100, 0, foreign_chain);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherChainMismatch,
        );
    }

    #[test]
    fn now_equals_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 100, 500);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 500),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn now_past_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 100, 500);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 501),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn negative_expires_at_fails_closed() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 100, -1);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn cumulative_equals_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 250, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_below_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 100, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_zero_on_fresh_channel() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 0, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_above_deposit() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 501, 0);
        let msg = v.as_bytes();
        let parsed = valid_parsed(msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherOverDeposit,
        );
    }

    // --- Ed25519 structural failures (ed25519_ix::parse) -----------------

    /// Run `parse` and unwrap the expected error. Panics if parsing
    /// unexpectedly succeeds — structural-failure tests always pass
    /// deliberately malformed data.
    fn parse_err(data: &[u8]) -> ed25519_ix::Ed25519ParseError {
        ed25519_ix::parse(data).err().expect("parse should fail")
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
    fn message_data_size_above_canonical_48() {
        // Canonical 160-byte ix, but overwrite the declared
        // `message_data_size` field at offsets[10..12] (= data[12..14])
        // to 49. Length guard passes; the dedicated size-check fires.
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data[12..14].copy_from_slice(&49u16.to_le_bytes());
        assert_eq!(parse_err(&data), ed25519_ix::Ed25519ParseError::MessageSize);
    }

    #[test]
    fn message_data_size_below_canonical_48() {
        let mut data = build_ix_data(
            AUTH.as_array(),
            &[0u8; VOUCHER_PAYLOAD_SIZE],
            &AUTH_SIGNATURE,
        );
        data[12..14].copy_from_slice(&47u16.to_le_bytes());
        assert_eq!(parse_err(&data), ed25519_ix::Ed25519ParseError::MessageSize);
    }

    #[test]
    fn ix_data_shorter_than_canonical() {
        // 159 bytes — one shy of the canonical 160-byte layout. Must
        // fail fast before any offsets are read, so short ixs return a
        // clean error instead of panicking on out-of-bounds indexing.
        let short = [0u8; 159];
        assert_eq!(parse_err(&short), ed25519_ix::Ed25519ParseError::Length);
    }

    #[test]
    fn ix_data_longer_than_canonical() {
        // 161 bytes — trailing byte past the pinned layout.
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

    #[test]
    fn message_off_by_one_byte() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 100, 0);
        let mut msg: Vec<u8> = v.as_bytes().to_vec();
        msg[0] ^= 1;
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherMessageMismatch,
        );
    }

    #[test]
    fn precompile_pubkey_not_authorized_signer() {
        let ch = make_channel(0, 500, AUTH);
        let v = mk_voucher(CHANNEL_ID, 100, 0);
        let msg = v.as_bytes();
        let parsed = ed25519_ix::Parsed {
            pubkey: OTHER_PUBKEY.as_array(),
            message: msg
                .try_into()
                .expect("test message must be VOUCHER_PAYLOAD_SIZE"),
        };
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherSignerMismatch,
        );
    }
}
