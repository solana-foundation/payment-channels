#[derive(Debug)]
pub(crate) enum TokenExtensionError {
    MalformedTokenAccountData,
    UnsupportedTokenExtension,
    /// Allow-listed but live: nonzero transfer fee or installed hook program.
    ActiveTokenExtension,
}

pub(crate) mod base_layout {
    use pinocchio_token_2022::state::{Account as TokenAccount, Mint as TokenMint};

    /// SPL Token mint byte length. Token-2022 mints with extensions are
    /// longer; the gap between this and `TOKEN_ACCOUNT_LEN` is enforced to be
    /// all-zero so a Mint can never be misread as an Account with extensions.
    pub(crate) const MINT_LEN: usize = TokenMint::BASE_LEN;

    /// SPL Token account byte length. Token-2022 account extensions follow
    /// the base account region; Token-2022 mints share this offset for the
    /// account-type discriminator byte.
    pub(crate) const TOKEN_ACCOUNT_LEN: usize = TokenAccount::BASE_LEN;
}

pub(crate) mod tlv {
    use core::mem::size_of;
    use pinocchio_token_2022::state::AccountType;

    /// Length of a TLV `type` field (`u16`).
    pub(crate) const TYPE_LEN: usize = size_of::<u16>();
    /// Length of a TLV `length` field (`u16`).
    pub(crate) const LENGTH_LEN: usize = size_of::<u16>();
    /// Token-2022 writes an account-type byte at this shared offset before TLV
    /// extension data for both mints and token accounts.
    pub(crate) const ACCOUNT_TYPE_OFFSET: usize = super::base_layout::TOKEN_ACCOUNT_LEN;
    /// First byte of the TLV trailer — immediately after the account-type
    /// discriminator byte.
    pub(crate) const START: usize = ACCOUNT_TYPE_OFFSET + size_of::<AccountType>();
    /// TLV header layout: `u16 type | u16 length`.
    pub(crate) const HEADER_LEN: usize = TYPE_LEN + LENGTH_LEN;
}

/// Sentinel `type` field marking the end of the populated TLV trailer.
const UNINITIALIZED: u16 = 0;

use super::token_extensions::{ExtensionPolicy, ExtensionType};

/// One decoded TLV record.
pub(crate) struct ExtensionRecord<'a> {
    pub(crate) kind: ExtensionType,
    pub(crate) payload: &'a [u8],
}

/// Iterator over a Token-2022 TLV trailer. Stops at the `UNINITIALIZED`
/// sentinel or a trailer too short to encode a `type` field.
pub(crate) struct ExtensionTlv<'a> {
    remaining: &'a [u8],
}

impl<'a> ExtensionTlv<'a> {
    pub(crate) fn new(trailer: &'a [u8]) -> Self {
        Self { remaining: trailer }
    }

    fn advance_one(&mut self) -> Result<Option<ExtensionRecord<'a>>, TokenExtensionError> {
        if self.remaining.len() < tlv::TYPE_LEN {
            // A trailing slice shorter than a `type` field can only be
            // legitimate if it's all zero (terminator pad). A stray nonzero
            // byte is a wire-format violation.
            if self.remaining.iter().any(|&b| b != 0) {
                return Err(TokenExtensionError::MalformedTokenAccountData);
            }
            return Ok(None);
        }

        let raw_type = u16::from_le_bytes([self.remaining[0], self.remaining[1]]);
        if raw_type == UNINITIALIZED {
            return Ok(None);
        }

        if self.remaining.len() < tlv::HEADER_LEN {
            return Err(TokenExtensionError::MalformedTokenAccountData);
        }
        let kind = ExtensionType::try_from(raw_type)?;
        let value_len = u16::from_le_bytes([self.remaining[2], self.remaining[3]]) as usize;
        let next_offset = tlv::HEADER_LEN
            .checked_add(value_len)
            .ok_or(TokenExtensionError::MalformedTokenAccountData)?;
        if next_offset > self.remaining.len() {
            return Err(TokenExtensionError::MalformedTokenAccountData);
        }

        let payload = &self.remaining[tlv::HEADER_LEN..next_offset];
        self.remaining = &self.remaining[next_offset..];
        Ok(Some(ExtensionRecord { kind, payload }))
    }
}

impl<'a> Iterator for ExtensionTlv<'a> {
    type Item = Result<ExtensionRecord<'a>, TokenExtensionError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.advance_one() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => {
                // Sticky-fail: future calls land on the all-zero short-tail path and end.
                self.remaining = &[];
                Some(Err(e))
            }
        }
    }
}

/// Walks the Token-2022 TLV trailer and applies `policy` to every record.
/// Token-2022 rejects duplicate records at initialization; the walk is
/// duplicate-safe regardless, since every record must pass.
pub(crate) fn scan_tlv_extensions<P: ExtensionPolicy>(
    policy: &P,
    trailer: &[u8],
) -> Result<(), TokenExtensionError> {
    for record in ExtensionTlv::new(trailer) {
        let record = record?;
        policy.check(record.kind, record.payload)?;
    }
    Ok(())
}

#[cfg(test)]
mod tlv_tests {
    use super::*;
    use crate::instructions::helpers::token_extensions::{
        MintExtensionPolicy, TokenAccountExtensionPolicy,
    };

    const MINT: MintExtensionPolicy = MintExtensionPolicy { epoch: 0 };

    fn header(extension_type: u16, value_len: u16) -> [u8; 4] {
        let t = extension_type.to_le_bytes();
        let l = value_len.to_le_bytes();
        [t[0], t[1], l[0], l[1]]
    }

    fn expect_err(result: Result<(), TokenExtensionError>, expected: TokenExtensionError) {
        match result {
            Ok(()) => panic!("expected error, got Ok"),
            Err(e) => assert_eq!(e as u32, expected as u32),
        }
    }

    #[test]
    fn uninitialized_sentinel_matches_upstream() {
        use spl_token_2022_interface::extension::ExtensionType as Upstream;
        assert_eq!(UNINITIALIZED, Upstream::Uninitialized as u16);
    }

    #[test]
    fn scan_accepts_empty_trailer() {
        assert!(scan_tlv_extensions(&MINT, &[]).is_ok());
        assert!(scan_tlv_extensions(&TokenAccountExtensionPolicy, &[]).is_ok());
    }

    #[test]
    fn scan_accepts_single_whitelisted_mint_extension() {
        let bytes = header(ExtensionType::MetadataPointer as u16, 0);
        assert!(scan_tlv_extensions(&MINT, &bytes).is_ok());
    }

    #[test]
    fn scan_accepts_chained_whitelisted_mint_extensions() {
        let h1 = header(ExtensionType::MetadataPointer as u16, 2);
        let h2 = header(ExtensionType::TokenMetadata as u16, 1);
        let bytes: [u8; 11] = [
            h1[0], h1[1], h1[2], h1[3], 0xAA, 0xBB, h2[0], h2[1], h2[2], h2[3], 0xCC,
        ];
        assert!(scan_tlv_extensions(&MINT, &bytes).is_ok());
    }

    #[test]
    fn scan_terminates_on_uninitialized_header() {
        let h1 = header(UNINITIALIZED, 0);
        let h2 = header(0xFFFF, 0);
        let bytes: [u8; 8] = [h1[0], h1[1], h1[2], h1[3], h2[0], h2[1], h2[2], h2[3]];
        assert!(scan_tlv_extensions(&MINT, &bytes).is_ok());
    }

    #[test]
    fn scan_terminates_on_uninitialized_sentinel_in_trailer() {
        // The first two zero bytes after the whitelisted entry decode to
        // UNINITIALIZED and end the walk; the remaining tail is unread.
        let h = header(ExtensionType::MetadataPointer as u16, 0);
        let mut bytes = [0u8; 4 + 64];
        bytes[..4].copy_from_slice(&h);
        assert!(scan_tlv_extensions(&MINT, &bytes).is_ok());
    }

    #[test]
    fn scan_rejects_truncated_header() {
        let bytes = [0x12, 0x00, 0x01];
        expect_err(
            scan_tlv_extensions(&MINT, &bytes),
            TokenExtensionError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_accepts_single_trailing_zero_byte() {
        // Below the 2-byte type field; the all-zero terminator pad is benign.
        assert!(scan_tlv_extensions(&MINT, &[0x00]).is_ok());
    }

    #[test]
    fn scan_rejects_single_trailing_nonzero_byte() {
        // Below the 2-byte type field but nonzero — wire-format violation.
        expect_err(
            scan_tlv_extensions(&MINT, &[0xFF]),
            TokenExtensionError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_rejects_two_trailing_bytes_as_whitelisted_type() {
        // type=METADATA_POINTER (whitelisted) but no length bytes follow.
        let bytes = [0x12, 0x00];
        expect_err(
            scan_tlv_extensions(&MINT, &bytes),
            TokenExtensionError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_rejects_two_trailing_bytes_as_forbidden_type() {
        // type=NonTransferable (9), but without length bytes the TLV
        // record is malformed before extension policy is meaningful.
        let bytes = [0x09, 0x00];
        expect_err(
            scan_tlv_extensions(&MINT, &bytes),
            TokenExtensionError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_accepts_value_len_reaching_buffer_end() {
        let h = header(ExtensionType::MetadataPointer as u16, 4);
        let bytes: [u8; 8] = [h[0], h[1], h[2], h[3], 0xAA, 0xBB, 0xCC, 0xDD];
        assert!(scan_tlv_extensions(&MINT, &bytes).is_ok());
    }

    #[test]
    fn scan_rejects_value_len_overflowing_remaining() {
        // declared value_len=8, only 4 payload bytes supplied
        let h = header(ExtensionType::MetadataPointer as u16, 8);
        let bytes: [u8; 8] = [h[0], h[1], h[2], h[3], 0, 0, 0, 0];
        expect_err(
            scan_tlv_extensions(&MINT, &bytes),
            TokenExtensionError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_rejects_non_whitelisted_type() {
        let bytes = header(0xFFFF, 0);
        expect_err(
            scan_tlv_extensions(&MINT, &bytes),
            TokenExtensionError::UnsupportedTokenExtension,
        );
    }

    #[test]
    fn scan_rejects_mint_only_id_on_token_account() {
        let bytes = header(ExtensionType::MetadataPointer as u16, 0);
        expect_err(
            scan_tlv_extensions(&TokenAccountExtensionPolicy, &bytes),
            TokenExtensionError::UnsupportedTokenExtension,
        );
    }

    #[test]
    fn extension_tlv_iterator_yields_typed_records_and_advances_past_values() {
        let h1 = header(ExtensionType::MetadataPointer as u16, 2);
        let h2 = header(ExtensionType::TokenMetadata as u16, 1);
        let bytes: [u8; 11] = [
            h1[0], h1[1], h1[2], h1[3], 0xAA, 0xBB, h2[0], h2[1], h2[2], h2[3], 0xCC,
        ];
        let mut it = ExtensionTlv::new(&bytes);
        let first = it.next().expect("first").expect("ok");
        assert_eq!(first.kind, ExtensionType::MetadataPointer);
        assert_eq!(first.payload, &[0xAA, 0xBB]);
        let second = it.next().expect("second").expect("ok");
        assert_eq!(second.kind, ExtensionType::TokenMetadata);
        assert_eq!(second.payload, &[0xCC]);
        assert!(it.next().is_none());
    }
}
