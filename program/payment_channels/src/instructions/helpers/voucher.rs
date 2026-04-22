//! Voucher verification.
//!
//! Parses the caller-bundled Ed25519 precompile ix from the Instructions
//! sysvar at `current - 1`, reconstructs the signed payload, and checks
//! binding / freshness / cap / strict monotonicity / message / signer /
//! signature cross-check against the channel state. Pure validator; the
//! caller is responsible for writing [`Channel::settled`] back.

use pinocchio::{AccountView, Address, error::ProgramError, sysvars::instructions::Instructions};

use crate::errors::PaymentChannelsError;
use crate::instructions::VoucherArgs;
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
    if ix.get_program_id() != &ed25519_ix::ED25519_PROGRAM_ID {
        return Err(PaymentChannelsError::MissingEd25519Verification.into());
    }
    let parsed = ed25519_ix::parse(ix.get_instruction_data())?;
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

    let expires_at: i64 = voucher.expires_at;
    if expires_at != 0 && now_unix >= expires_at {
        return Err(PaymentChannelsError::VoucherExpired.into());
    }

    let cumulative: u64 = voucher.cumulative_amount;
    let deposit: u64 = channel.deposit;
    if cumulative > deposit {
        return Err(PaymentChannelsError::VoucherOverDeposit.into());
    }

    let settled: u64 = channel.settled;
    if settled >= cumulative {
        return Err(PaymentChannelsError::VoucherWatermarkNotMonotonic.into());
    }

    let payload = payload::build_signed_payload(voucher);
    if parsed.message != payload.as_slice() {
        return Err(PaymentChannelsError::VoucherMessageMismatch.into());
    }

    let authorized: Address = channel.authorized_signer;
    if parsed.pubkey != authorized.as_array() {
        return Err(PaymentChannelsError::VoucherSignerMismatch.into());
    }
    let v_signer: Address = voucher.signer;
    if v_signer != authorized {
        return Err(PaymentChannelsError::VoucherSignerMismatch.into());
    }

    let v_sig: [u8; 64] = voucher.signature;
    if parsed.signature != v_sig {
        return Err(PaymentChannelsError::VoucherSignatureCrossCheckFailed.into());
    }

    Ok(cumulative)
}

mod payload {
    use super::{Address, VoucherArgs};

    /// Byte length of the signed voucher payload — `channel_id (32) ||
    /// cumulative_amount (8 LE) || expires_at (8 LE)`. Also the canonical
    /// `message_data_size` the Ed25519 precompile ix must declare; pinned
    /// by [`super::ed25519_ix::parse`] against a layout where an attacker has the
    /// precompile verify a truncated or extended message.
    pub(super) const VOUCHER_PAYLOAD_SIZE: usize = 48;

    /// Borsh(`Voucher { channel_id, cumulative_amount, expires_at }`).
    /// Hand-rolled because the 48-byte layout is part of the off-chain
    /// signer contract.
    pub(super) fn build_signed_payload(v: &VoucherArgs) -> [u8; VOUCHER_PAYLOAD_SIZE] {
        let channel_id: Address = v.channel_id;
        let cumulative: u64 = v.cumulative_amount;
        let expires_at: i64 = v.expires_at;

        let mut out = [0u8; VOUCHER_PAYLOAD_SIZE];
        out[..32].copy_from_slice(channel_id.as_array());
        out[32..40].copy_from_slice(&cumulative.to_le_bytes());
        out[40..48].copy_from_slice(&expires_at.to_le_bytes());
        out
    }
}

mod ed25519_ix {
    //! Ed25519 precompile ix parser.
    //!
    //! All magic constants and layouts are sourced from the official Solana documentation.
    //! https://solana.com/docs/core/programs/precompiles#verify-ed25519-signature

    use super::{PaymentChannelsError, payload::VOUCHER_PAYLOAD_SIZE};
    use pinocchio::{Address, error::ProgramError};

    /// Native program address of Ed25519SigVerify precompile.
    pub(super) const ED25519_PROGRAM_ID: Address =
        Address::from_str_const("Ed25519SigVerify111111111111111111111111111");

    /// Ed25519 pubkey byte width.
    const PUBKEY_SERIALIZED_SIZE: usize = 32;

    /// Ed25519 signature byte width.
    const SIGNATURE_SERIALIZED_SIZE: usize = 64;

    /// Byte position of the `Ed25519SignatureOffsets` array — sits
    /// immediately after the `[num_signatures: u8, padding: u8]`
    /// header.
    const SIGNATURE_OFFSETS_START: usize = 2;

    /// Byte width of one `Ed25519SignatureOffsets` record: seven
    /// little-endian `u16` fields, in order — `signature_offset`,
    /// `signature_instruction_index`, `public_key_offset`,
    /// `public_key_instruction_index`, `message_data_offset`,
    /// `message_data_size`, `message_instruction_index`.
    const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;

    /// Canonical byte offset of the pubkey region in a single-signature
    /// inline ix (= 16): the first byte after the two-byte header plus
    /// one offsets record.
    const PUBKEY_OFFSET: usize = SIGNATURE_OFFSETS_START + SIGNATURE_OFFSETS_SERIALIZED_SIZE;

    /// Canonical byte offset of the signature region (= 48): pubkey
    /// region immediately followed by the 64-byte signature.
    const SIGNATURE_OFFSET: usize = PUBKEY_OFFSET + PUBKEY_SERIALIZED_SIZE;

    /// Canonical byte offset of the message payload (= 112): signature
    /// region immediately followed by the message. Message length is
    /// taken from `message_data_size` (offsets[10..12]).
    const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SERIALIZED_SIZE;

    /// Parsed Ed25519 precompile ix data.
    pub(super) struct Parsed<'a> {
        /// Ed25519 pubkey.
        pub pubkey: &'a [u8],
        /// Ed25519 signature.
        pub signature: &'a [u8],
        /// Ed25519 message.
        pub message: &'a [u8],
    }

    /// Parse a single-signature Ed25519 precompile ix with the canonical
    /// inline layout. Validates every field of `Ed25519SignatureOffsets`.
    pub(super) fn parse(data: &[u8]) -> Result<Parsed<'_>, ProgramError> {
        // Full canonical inline layout: `[num_sigs=1, pad=0, offsets×1, pubkey, signature, message]`.
        // Guard — `num_signatures == 1`. N = 0 verifies nothing; N > 1
        // appends further offsets records whose signatures we never
        // parse, so the surrounding ix could appear "verified" while
        // those riders covered arbitrary attacker-chosen bytes.
        if data[0] != 1 {
            return Err(PaymentChannelsError::MalformedEd25519Instruction.into());
        }

        // Read the offset fields.
        let offsets = &data[SIGNATURE_OFFSETS_START..PUBKEY_OFFSET];

        let read = |i: usize| u16::from_le_bytes([offsets[i], offsets[i + 1]]);
        let signature_offset = read(0);
        let sig_ix = read(2);
        let public_key_offset = read(4);
        let pk_ix = read(6);
        let message_data_offset = read(8);
        let message_data_size = read(10);
        let msg_ix = read(12);

        // Guard — cross-instruction indirection.
        // Native sentinel to force the precompile to read from our ix.
        if sig_ix != u16::MAX || pk_ix != u16::MAX || msg_ix != u16::MAX {
            return Err(PaymentChannelsError::MalformedEd25519Instruction.into());
        }

        // Guard — canonical byte offsets. The precompile accepts any
        // in-bounds offsets, so without these pins a non-canonical
        // layout could verify cryptographically while our hardcoded
        // `data[16..48]` / `data[48..112]` reads land on different
        // bytes than the precompile checked. Payload-match downstream
        // would still catch the bypass (unless the signer explicitly
        // signed the wrong-position bytes), but pinning here keeps
        // slice bounds compile-time constant and narrows the off-chain
        // signer contract to one wire encoding.
        if public_key_offset as usize != PUBKEY_OFFSET
            || signature_offset as usize != SIGNATURE_OFFSET
            || message_data_offset as usize != MESSAGE_OFFSET
        {
            return Err(PaymentChannelsError::MalformedEd25519Instruction.into());
        }

        // Guard — canonical message length (48 B: `channel_id ||
        // cumulative_amount || expires_at`, LE).
        if message_data_size as usize != VOUCHER_PAYLOAD_SIZE {
            return Err(PaymentChannelsError::MalformedEd25519Instruction.into());
        }

        let message = &data[MESSAGE_OFFSET..MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE];

        Ok(Parsed {
            pubkey: &data[PUBKEY_OFFSET..SIGNATURE_OFFSET],
            signature: &data[SIGNATURE_OFFSET..MESSAGE_OFFSET],
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    const CHANNEL_ID: Address = Address::new_from_array([7u8; 32]);
    /// Channel authorized signer.
    const AUTH: Address = Address::new_from_array([66u8; 32]);
    /// Other pubkey for wrong-pubkey tests.
    const OTHER_PUBKEY: Address = Address::new_from_array([85u8; 32]);
    /// Voucher Signature.
    const AUTH_SIGNATURE: [u8; 64] = [154u8; 64];

    /// Build a [`Channel`] for fixtures: only the fields the voucher
    /// path reads (`settled`, `deposit`, `authorized_signer`) are set;
    /// everything else is zero.
    fn make_channel(settled: u64, deposit: u64, authorized_signer: Address) -> Channel {
        let bytes = [0u8; Channel::LEN];
        let mut ch: Channel = unsafe { core::ptr::read(bytes.as_ptr() as *const Channel) };
        ch.deposit = deposit;
        ch.settled = settled;
        ch.authorized_signer = authorized_signer;
        ch
    }

    /// Assemble a [`VoucherArgs`] by logical argument order. Exists so
    /// tests don't have to know the `#[repr(C, packed)]` field order
    /// of the on-chain struct.
    fn make_voucher(
        channel_id: Address,
        cumulative: u64,
        expires_at: i64,
        signer: Address,
        signature: [u8; 64],
    ) -> VoucherArgs {
        VoucherArgs {
            cumulative_amount: cumulative,
            expires_at,
            channel_id,
            signer,
            signature,
        }
    }

    /// Encode an Ed25519 precompile ix in the canonical single-signature
    /// layout: `[num_sigs=1, pad=0, offsets×1, pubkey, signature, message]`.
    /// All three `*_instruction_index` fields are set to `u16::MAX` so
    /// `parse` accepts the output by default; tests that exercise guard
    /// failures tamper specific bytes of the returned buffer afterwards.
    fn build_ix_data(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Vec<u8> {
        let mut data = Vec::with_capacity(2 + 14 + 32 + 64 + message.len());
        data.push(1u8); // num_sigs
        data.push(0u8); // padding

        let header_len: u16 = 2 + 14;
        let pubkey_offset = header_len;
        let signature_offset = pubkey_offset + 32;
        let message_offset = signature_offset + 64;
        let message_size = message.len() as u16;

        data.extend_from_slice(&signature_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // signature_instruction_index
        data.extend_from_slice(&pubkey_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // pubkey_instruction_index
        data.extend_from_slice(&message_offset.to_le_bytes());
        data.extend_from_slice(&message_size.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // message_instruction_index

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

    /// Construct a [`ed25519_ix::Parsed`] that mirrors what `parse`
    /// returns for a canonical precompile ix "signed" by [`AUTH`]. Lets
    /// `verify_parsed`-only tests skip both the parse pipeline and
    /// the sysvar plumbing that `verify_voucher` would run.
    fn valid_parsed(message: &[u8]) -> ed25519_ix::Parsed<'_> {
        ed25519_ix::Parsed {
            pubkey: AUTH.as_array(),
            signature: &AUTH_SIGNATURE,
            message,
        }
    }

    // --- payload contract -------------------------------------------------

    #[test]
    fn payload_matches_borsh_voucher_struct() {
        const SAMPLE_CUMULATIVE: u64 = u64::from_le_bytes([239, 205, 171, 137, 103, 69, 35, 1]);
        #[derive(borsh::BorshSerialize)]
        struct Voucher {
            channel_id: [u8; 32],
            cumulative_amount: u64,
            expires_at: i64,
        }
        let args = make_voucher(CHANNEL_ID, SAMPLE_CUMULATIVE, -1i64, AUTH, AUTH_SIGNATURE);
        let built = payload::build_signed_payload(&args);
        let borshed = borsh::to_vec(&Voucher {
            channel_id: *CHANNEL_ID.as_array(),
            cumulative_amount: SAMPLE_CUMULATIVE,
            expires_at: -1i64,
        })
        .unwrap();
        assert_eq!(built.as_slice(), borshed.as_slice());
        assert_eq!(built.len(), 48);
    }

    #[test]
    fn payload_layout_channel_id_first_then_cumulative_then_expiry() {
        const CUMULATIVE: u64 = u64::from_le_bytes([119, 102, 85, 68, 51, 34, 17, 0]);
        const EXPIRES_AT: i64 = i64::from_le_bytes([248, 249, 250, 251, 252, 253, 254, 127]);
        let args = make_voucher(CHANNEL_ID, CUMULATIVE, EXPIRES_AT, AUTH, AUTH_SIGNATURE);
        let built = payload::build_signed_payload(&args);
        assert_eq!(&built[..32], CHANNEL_ID.as_array());
        assert_eq!(&built[32..40], &CUMULATIVE.to_le_bytes());
        assert_eq!(&built[40..48], &EXPIRES_AT.to_le_bytes());
    }

    // --- happy paths ------------------------------------------------------

    #[test]
    fn ok_strict_monotonic_no_expiry() {
        let ch = make_channel(100, 1_000, AUTH);
        let v = make_voucher(CHANNEL_ID, 200, 0, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        let out = verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 1_000_000).unwrap();
        assert_eq!(out, 200);
    }

    #[test]
    fn ok_expiry_in_future() {
        let ch = make_channel(100, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 500, 2_000, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        let out = verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 1_999).unwrap();
        assert_eq!(out, 500);
    }

    // --- binding / freshness / monotonicity / cap ------------------------

    #[test]
    fn wrong_channel_id() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(
            Address::new_from_array([9u8; 32]),
            100,
            0,
            AUTH,
            AUTH_SIGNATURE,
        );
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherChannelMismatch,
        );
    }

    #[test]
    fn now_equals_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, 500, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 500),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn now_past_expires_at() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, 500, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 501),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn negative_expires_at_fails_closed() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, -1, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherExpired,
        );
    }

    #[test]
    fn cumulative_equals_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 250, 0, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_below_settled() {
        let ch = make_channel(250, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, 0, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_zero_on_fresh_channel() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 0, 0, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherWatermarkNotMonotonic,
        );
    }

    #[test]
    fn cumulative_above_deposit() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 501, 0, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherOverDeposit,
        );
    }

    // --- Ed25519 structural failures (ed25519_ix::parse) -----------------

    /// Run `parse` and unwrap the expected error. Panics if parsing
    /// unexpectedly succeeds — structural-failure tests always pass
    /// deliberately malformed data.
    fn parse_err(data: &[u8]) -> ProgramError {
        ed25519_ix::parse(data).err().expect("parse should fail")
    }

    /// Assert `err` is specifically
    /// [`PaymentChannelsError::MalformedEd25519Instruction`]. Every
    /// `parse`-path guard returns this variant, so structural tests
    /// share this assertion instead of inlining `expect_err` each time.
    fn assert_malformed(err: ProgramError) {
        match err {
            ProgramError::Custom(c) => {
                assert_eq!(c, PaymentChannelsError::MalformedEd25519Instruction as u32)
            }
            other => panic!("expected MalformedEd25519Instruction, got {:?}", other),
        }
    }

    #[test]
    fn num_signatures_zero() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        data[0] = 0;
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn num_signatures_two() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        data[0] = 2;
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn signature_offset_non_canonical() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        // signature_offset sits at offsets[0..2] → data[2..4]
        data[2..4].copy_from_slice(&49u16.to_le_bytes());
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn public_key_offset_non_canonical() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        // public_key_offset sits at offsets[4..6] → data[6..8]
        data[6..8].copy_from_slice(&17u16.to_le_bytes());
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn message_data_offset_non_canonical() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        // message_data_offset sits at offsets[8..10] → data[10..12]
        data[10..12].copy_from_slice(&113u16.to_le_bytes());
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn message_data_size_not_canonical_48() {
        // build_ix_data writes `msg_size = message.len()`, so a 49-byte
        // message makes the declared `message_data_size` = 49.
        let data = build_ix_data(AUTH.as_array(), &[0u8; 49], &AUTH_SIGNATURE);
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn message_data_size_below_canonical_48() {
        let data = build_ix_data(AUTH.as_array(), &[0u8; 47], &AUTH_SIGNATURE);
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn signature_instruction_index_not_u16_max() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        // offsets[2..4] is signature_instruction_index
        data[4] = 0;
        data[5] = 0;
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn public_key_instruction_index_not_u16_max() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        // offsets[6..8] is pubkey_instruction_index
        data[8] = 0;
        data[9] = 0;
        assert_malformed(parse_err(&data));
    }

    #[test]
    fn message_instruction_index_not_u16_max() {
        let mut data = build_ix_data(AUTH.as_array(), b"msg", &AUTH_SIGNATURE);
        // offsets[12..14] is message_instruction_index
        data[14] = 0;
        data[15] = 0;
        assert_malformed(parse_err(&data));
    }

    // --- Ed25519 content failures ----------------------------------------

    #[test]
    fn message_off_by_one_byte() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, 0, AUTH, AUTH_SIGNATURE);
        let mut msg: Vec<u8> = payload::build_signed_payload(&v).to_vec();
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
        let v = make_voucher(CHANNEL_ID, 100, 0, AUTH, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = ed25519_ix::Parsed {
            pubkey: OTHER_PUBKEY.as_array(),
            signature: &AUTH_SIGNATURE,
            message: &msg,
        };
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherSignerMismatch,
        );
    }

    #[test]
    fn wire_signer_not_authorized_signer() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, 0, OTHER_PUBKEY, AUTH_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherSignerMismatch,
        );
    }

    #[test]
    fn signature_cross_check_fails() {
        const OTHER_SIGNATURE: [u8; 64] = [119u8; 64];
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, 0, AUTH, OTHER_SIGNATURE);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherSignatureCrossCheckFailed,
        );
    }

    #[test]
    fn all_zero_wire_signature_with_valid_precompile() {
        let ch = make_channel(0, 500, AUTH);
        let v = make_voucher(CHANNEL_ID, 100, 0, AUTH, [0u8; 64]);
        let msg = payload::build_signed_payload(&v);
        let parsed = valid_parsed(&msg);
        expect_err(
            verify_parsed(&CHANNEL_ID, &ch, &v, &parsed, 0),
            PaymentChannelsError::VoucherSignatureCrossCheckFailed,
        );
    }
}
