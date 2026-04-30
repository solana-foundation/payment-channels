use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer};
use pinocchio_token_2022::instructions::TransferChecked;

use crate::errors::PaymentChannelsError;

pub(crate) mod base_layout {
    use pinocchio_token_2022::state::{Account as TokenAccount, Mint as TokenMint};

    /// SPL classic mint byte length. Token-2022 mints with extensions are
    /// longer; the gap between this and `TOKEN_ACCOUNT_LEN` is enforced to be
    /// all-zero so a Mint can never be misread as an Account with extensions.
    pub(crate) const MINT_LEN: usize = TokenMint::BASE_LEN;

    /// SPL classic token account byte length. Token-2022 account extensions
    /// follow the base account region; Token-2022 mints share this offset for
    /// the account-type discriminator byte.
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

/// Token-2022 extension type ids accepted by this program. They are part of
/// the Token-2022 TLV wire format and intentionally mirrored here to keep this
/// program no-alloc/no-std. Asserted against upstream in the test module.
mod extension_id {
    /// Sentinel for an empty TLV slot — terminates the extension walk.
    pub(crate) const UNINITIALIZED: u16 = 0;
    /// Token-account-only: locks the `owner` field after initialization.
    pub(crate) const IMMUTABLE_OWNER: u16 = 7;
    /// Mint-only: pointer to off-chain or inline metadata; transfer-amount-neutral.
    pub(crate) const METADATA_POINTER: u16 = 18;
    /// Mint-only: inline metadata payload paired with `METADATA_POINTER`.
    pub(crate) const TOKEN_METADATA: u16 = 19;
    /// Mint-only: pointer to a token-group account; transfer-amount-neutral.
    pub(crate) const GROUP_POINTER: u16 = 20;
    /// Mint-only: inline group payload paired with `GROUP_POINTER`.
    pub(crate) const TOKEN_GROUP: u16 = 21;
    /// Mint-only: pointer to a group-member account; transfer-amount-neutral.
    pub(crate) const GROUP_MEMBER_POINTER: u16 = 22;
    /// Mint-only: inline group-member payload paired with `GROUP_MEMBER_POINTER`.
    pub(crate) const TOKEN_GROUP_MEMBER: u16 = 23;
}

/// Returns the raw token amount from an already-validated token account.
pub fn token_account_amount(
    account: &AccountView,
    token_program: &Address,
    account_error: PaymentChannelsError,
) -> Result<u64, PaymentChannelsError> {
    if *token_program == pinocchio_token::ID {
        Ok(pinocchio_token::state::Account::from_account_view(account)
            .map_err(|_| account_error)?
            .amount())
    } else if *token_program == pinocchio_token_2022::ID {
        Ok(
            pinocchio_token_2022::state::Account::from_account_view(account)
                .map_err(|_| account_error)?
                .amount(),
        )
    } else {
        Err(PaymentChannelsError::InvalidTokenProgram)
    }
}

/// Walks the Token-2022 TLV trailer and rejects any extension type not
/// whitelisted for the given account kind. The 2-byte `Uninitialized`
/// (0x0000) type field is the sole sentinel; a tail too short to encode a
/// type field cannot represent an extension and is treated as buffer end.
/// Duplicate entries of any type are rejected — Token-2022's on-chain
/// initializer enforces uniqueness, so a duplicate signals data the
/// program would never produce.
pub(crate) fn scan_tlv_extensions(
    mut data: &[u8],
    is_mint: bool,
) -> Result<(), PaymentChannelsError> {
    let mut seen: u32 = 0;
    while data.len() >= tlv::TYPE_LEN {
        let extension_type = u16::from_le_bytes([data[0], data[1]]);
        if extension_type == extension_id::UNINITIALIZED {
            return Ok(());
        }

        if !extension_allowed(extension_type, is_mint) {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions);
        }

        // Whitelisted ids fit in 0..32 (max id is TOKEN_GROUP_MEMBER = 23),
        // so a u32 bitmask suffices to dedupe. The whitelist check above
        // bounds the shift below 32 — reordering would invite UB.
        let bit = 1u32 << (extension_type as u32);
        if seen & bit != 0 {
            return Err(PaymentChannelsError::DuplicateTokenExtension);
        }
        seen |= bit;

        if data.len() < tlv::HEADER_LEN {
            return Err(PaymentChannelsError::MalformedTokenAccountData);
        }

        let value_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let next = tlv::HEADER_LEN
            .checked_add(value_len)
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
        if next > data.len() {
            return Err(PaymentChannelsError::MalformedTokenAccountData);
        }
        data = &data[next..];
    }

    Ok(())
}

/// Invokes a signed `TransferChecked` CPI from a channel-owned token account.
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked_signed(
    from: &AccountView,
    mint: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    amount: u64,
    decimals: u8,
    token_program: &Address,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }

    TransferChecked {
        from,
        mint,
        to,
        authority,
        amount,
        decimals,
        token_program,
    }
    .invoke_signed(signers)
}

/// Whitelist of Token-2022 extension type ids that are safe for this program:
/// metadata/group extensions on mints (no effect on transfer amount) and
/// `ImmutableOwner` on token accounts.
fn extension_allowed(extension_type: u16, is_mint: bool) -> bool {
    if is_mint {
        matches!(
            extension_type,
            extension_id::METADATA_POINTER
                | extension_id::TOKEN_METADATA
                | extension_id::GROUP_POINTER
                | extension_id::TOKEN_GROUP
                | extension_id::GROUP_MEMBER_POINTER
                | extension_id::TOKEN_GROUP_MEMBER
        )
    } else {
        extension_type == extension_id::IMMUTABLE_OWNER
    }
}

#[cfg(test)]
mod token_2022_extension_id_tests {
    use super::extension_id::*;
    use spl_token_2022_interface::extension::ExtensionType;

    #[test]
    fn mirrored_token_2022_extension_ids_match_upstream_wire_discriminants() {
        assert_eq!(UNINITIALIZED, ExtensionType::Uninitialized as u16);
        assert_eq!(IMMUTABLE_OWNER, ExtensionType::ImmutableOwner as u16);
        assert_eq!(METADATA_POINTER, ExtensionType::MetadataPointer as u16);
        assert_eq!(TOKEN_METADATA, ExtensionType::TokenMetadata as u16);
        assert_eq!(GROUP_POINTER, ExtensionType::GroupPointer as u16);
        assert_eq!(TOKEN_GROUP, ExtensionType::TokenGroup as u16);
        assert_eq!(
            GROUP_MEMBER_POINTER,
            ExtensionType::GroupMemberPointer as u16
        );
        assert_eq!(TOKEN_GROUP_MEMBER, ExtensionType::TokenGroupMember as u16);
    }
}

#[cfg(test)]
mod tlv_tests {
    use super::extension_id::*;
    use super::*;

    fn header(extension_type: u16, value_len: u16) -> [u8; 4] {
        let t = extension_type.to_le_bytes();
        let l = value_len.to_le_bytes();
        [t[0], t[1], l[0], l[1]]
    }

    fn expect_err(result: Result<(), PaymentChannelsError>, expected: PaymentChannelsError) {
        match result {
            Ok(()) => panic!("expected error, got Ok"),
            Err(e) => assert_eq!(e as u32, expected as u32),
        }
    }

    #[test]
    fn extension_allowed_mint_whitelist() {
        for id in [
            METADATA_POINTER,
            TOKEN_METADATA,
            GROUP_POINTER,
            TOKEN_GROUP,
            GROUP_MEMBER_POINTER,
            TOKEN_GROUP_MEMBER,
        ] {
            assert!(
                extension_allowed(id, true),
                "mint id {id} should be allowed"
            );
        }
    }

    #[test]
    fn extension_allowed_rejects_immutable_owner_on_mint() {
        assert!(!extension_allowed(IMMUTABLE_OWNER, true));
    }

    #[test]
    fn extension_allowed_token_account_whitelist() {
        assert!(extension_allowed(IMMUTABLE_OWNER, false));
        // Mint-only ids must not slip through on token accounts.
        for id in [
            METADATA_POINTER,
            TOKEN_METADATA,
            GROUP_POINTER,
            TOKEN_GROUP,
            GROUP_MEMBER_POINTER,
            TOKEN_GROUP_MEMBER,
        ] {
            assert!(
                !extension_allowed(id, false),
                "mint-only id {id} must not be allowed on token accounts",
            );
        }
    }

    #[test]
    fn extension_allowed_rejects_unknown_id() {
        assert!(!extension_allowed(0xFFFF, true));
        assert!(!extension_allowed(0xFFFF, false));
    }

    #[test]
    fn scan_accepts_empty_trailer() {
        assert!(scan_tlv_extensions(&[], true).is_ok());
        assert!(scan_tlv_extensions(&[], false).is_ok());
    }

    #[test]
    fn scan_accepts_single_whitelisted_mint_extension() {
        let bytes = header(METADATA_POINTER, 0);
        assert!(scan_tlv_extensions(&bytes, true).is_ok());
    }

    #[test]
    fn scan_accepts_chained_whitelisted_mint_extensions() {
        // [METADATA_POINTER hdr | 2-byte payload | TOKEN_METADATA hdr | 1-byte payload]
        let h1 = header(METADATA_POINTER, 2);
        let h2 = header(TOKEN_METADATA, 1);
        let bytes: [u8; 11] = [
            h1[0], h1[1], h1[2], h1[3], 0xAA, 0xBB, h2[0], h2[1], h2[2], h2[3], 0xCC,
        ];
        assert!(scan_tlv_extensions(&bytes, true).is_ok());
    }

    #[test]
    fn scan_rejects_duplicate_whitelisted_extension() {
        let h1 = header(METADATA_POINTER, 0);
        let h2 = header(METADATA_POINTER, 0);
        let bytes: [u8; 8] = [h1[0], h1[1], h1[2], h1[3], h2[0], h2[1], h2[2], h2[3]];
        expect_err(
            scan_tlv_extensions(&bytes, true),
            PaymentChannelsError::DuplicateTokenExtension,
        );
    }

    #[test]
    fn scan_terminates_on_uninitialized_header() {
        // UNINITIALIZED type byte short-circuits the walk, leaving the fake
        // out-of-whitelist tail unread.
        let h1 = header(UNINITIALIZED, 0);
        let h2 = header(0xFFFF, 0);
        let bytes: [u8; 8] = [h1[0], h1[1], h1[2], h1[3], h2[0], h2[1], h2[2], h2[3]];
        assert!(scan_tlv_extensions(&bytes, true).is_ok());
    }

    #[test]
    fn scan_terminates_on_uninitialized_sentinel_in_trailer() {
        // The first two zero bytes after the whitelisted entry decode to
        // UNINITIALIZED and end the walk; the remaining tail is unread.
        let h = header(METADATA_POINTER, 0);
        let mut bytes = [0u8; 4 + 64];
        bytes[..4].copy_from_slice(&h);
        assert!(scan_tlv_extensions(&bytes, true).is_ok());
    }

    #[test]
    fn scan_rejects_truncated_header() {
        let bytes = [0x12, 0x00, 0x01];
        expect_err(
            scan_tlv_extensions(&bytes, true),
            PaymentChannelsError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_accepts_single_trailing_zero_byte() {
        // Below the 2-byte type field; mirrors upstream's graceful tail.
        assert!(scan_tlv_extensions(&[0x00], true).is_ok());
    }

    #[test]
    fn scan_accepts_single_trailing_nonzero_byte() {
        assert!(scan_tlv_extensions(&[0xFF], true).is_ok());
    }

    #[test]
    fn scan_rejects_two_trailing_bytes_as_whitelisted_type() {
        // type=METADATA_POINTER (whitelisted) but no length bytes follow.
        let bytes = [0x12, 0x00];
        expect_err(
            scan_tlv_extensions(&bytes, true),
            PaymentChannelsError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_rejects_two_trailing_bytes_as_forbidden_type() {
        // type=TransferFeeConfig (1) — must be rejected before the length check.
        let bytes = [0x01, 0x00];
        expect_err(
            scan_tlv_extensions(&bytes, true),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
    }

    #[test]
    fn scan_accepts_value_len_reaching_buffer_end() {
        let h = header(METADATA_POINTER, 4);
        let bytes: [u8; 8] = [h[0], h[1], h[2], h[3], 0xAA, 0xBB, 0xCC, 0xDD];
        assert!(scan_tlv_extensions(&bytes, true).is_ok());
    }

    #[test]
    fn scan_rejects_value_len_overflowing_remaining() {
        // declared value_len=8, only 4 payload bytes supplied
        let h = header(METADATA_POINTER, 8);
        let bytes: [u8; 8] = [h[0], h[1], h[2], h[3], 0, 0, 0, 0];
        expect_err(
            scan_tlv_extensions(&bytes, true),
            PaymentChannelsError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_rejects_non_whitelisted_type() {
        let bytes = header(0xFFFF, 0);
        expect_err(
            scan_tlv_extensions(&bytes, true),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
    }

    #[test]
    fn scan_rejects_mint_only_id_on_token_account() {
        let bytes = header(METADATA_POINTER, 0);
        expect_err(
            scan_tlv_extensions(&bytes, false),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
    }
}
