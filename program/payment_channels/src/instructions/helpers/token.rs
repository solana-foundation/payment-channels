use pinocchio::{ProgramResult, cpi::Signer};
use pinocchio_token_2022::instructions::TransferChecked;

use crate::{
    errors::PaymentChannelsError,
    helpers::view::{
        AnyTokenAccountsView, ChannelAccountView, ChannelTokenAccountView, Checked,
        MintAccountView, TokenProgramAccountView,
    },
};

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

/// Token-2022 extension type ids accepted by this program. Discriminants are
/// part of the Token-2022 wire format; mirrored here so the program stays
/// no_std/no_alloc. Asserted against upstream in the test module.
#[repr(u16)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum ExtensionType {
    /// Token-account-only: locks the `owner` field after initialization.
    ImmutableOwner = 7,
    /// Mint-only: pointer to off-chain or inline metadata; transfer-amount-neutral.
    MetadataPointer = 18,
    /// Mint-only: inline metadata payload paired with `MetadataPointer`.
    TokenMetadata = 19,
    /// Mint-only: pointer to a token-group account; transfer-amount-neutral.
    GroupPointer = 20,
    /// Mint-only: inline group payload paired with `GroupPointer`.
    TokenGroup = 21,
    /// Mint-only: pointer to a group-member account; transfer-amount-neutral.
    GroupMemberPointer = 22,
    /// Mint-only: inline group-member payload paired with `GroupMemberPointer`.
    TokenGroupMember = 23,
}

impl TryFrom<u16> for ExtensionType {
    type Error = PaymentChannelsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const IMMUTABLE_OWNER: u16 = ExtensionType::ImmutableOwner as u16;
        const METADATA_POINTER: u16 = ExtensionType::MetadataPointer as u16;
        const TOKEN_METADATA: u16 = ExtensionType::TokenMetadata as u16;
        const GROUP_POINTER: u16 = ExtensionType::GroupPointer as u16;
        const TOKEN_GROUP: u16 = ExtensionType::TokenGroup as u16;
        const GROUP_MEMBER_POINTER: u16 = ExtensionType::GroupMemberPointer as u16;
        const TOKEN_GROUP_MEMBER: u16 = ExtensionType::TokenGroupMember as u16;

        match value {
            IMMUTABLE_OWNER => Ok(Self::ImmutableOwner),
            METADATA_POINTER => Ok(Self::MetadataPointer),
            TOKEN_METADATA => Ok(Self::TokenMetadata),
            GROUP_POINTER => Ok(Self::GroupPointer),
            TOKEN_GROUP => Ok(Self::TokenGroup),
            GROUP_MEMBER_POINTER => Ok(Self::GroupMemberPointer),
            TOKEN_GROUP_MEMBER => Ok(Self::TokenGroupMember),
            _ => Err(PaymentChannelsError::UnsupportedTokenExtensions),
        }
    }
}

/// Whitelist of TLV extension types accepted for a given account kind.
pub(crate) trait ExtensionPolicy {
    fn allows(&self, ext: ExtensionType) -> bool;
}

pub(crate) struct MintExtensionPolicy;
pub(crate) struct TokenAccountExtensionPolicy;

impl ExtensionPolicy for MintExtensionPolicy {
    fn allows(&self, ext: ExtensionType) -> bool {
        matches!(
            ext,
            ExtensionType::MetadataPointer
                | ExtensionType::TokenMetadata
                | ExtensionType::GroupPointer
                | ExtensionType::TokenGroup
                | ExtensionType::GroupMemberPointer
                | ExtensionType::TokenGroupMember,
        )
    }
}

impl ExtensionPolicy for TokenAccountExtensionPolicy {
    fn allows(&self, ext: ExtensionType) -> bool {
        matches!(ext, ExtensionType::ImmutableOwner)
    }
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
}

impl<'a> Iterator for ExtensionTlv<'a> {
    type Item = Result<ExtensionType, PaymentChannelsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.len() < tlv::TYPE_LEN {
            return None;
        }

        let raw_type = u16::from_le_bytes([self.remaining[0], self.remaining[1]]);
        if raw_type == UNINITIALIZED {
            return None;
        }

        // Type whitelist is checked before the header-length probe so a
        // forbidden 2-byte tail surfaces as `UnsupportedTokenExtensions`
        // rather than `MalformedTokenAccountData`.
        let kind = match ExtensionType::try_from(raw_type) {
            Ok(k) => k,
            Err(e) => {
                self.remaining = &[];
                return Some(Err(e));
            }
        };

        if self.remaining.len() < tlv::HEADER_LEN {
            self.remaining = &[];
            return Some(Err(PaymentChannelsError::MalformedTokenAccountData));
        }

        let value_len = u16::from_le_bytes([self.remaining[2], self.remaining[3]]) as usize;
        let next_offset = match tlv::HEADER_LEN.checked_add(value_len) {
            Some(n) => n,
            None => {
                self.remaining = &[];
                return Some(Err(PaymentChannelsError::ArithmeticOverflow));
            }
        };
        if next_offset > self.remaining.len() {
            self.remaining = &[];
            return Some(Err(PaymentChannelsError::MalformedTokenAccountData));
        }

        self.remaining = &self.remaining[next_offset..];
        Some(Ok(kind))
    }
}

/// Walks the Token-2022 TLV trailer and rejects any type not whitelisted by
/// `policy`. Extension uniqueness is enforced by the upstream initializer.
pub(crate) fn scan_tlv_extensions(
    trailer: &[u8],
    policy: &impl ExtensionPolicy,
) -> Result<(), PaymentChannelsError> {
    for kind in ExtensionTlv::new(trailer) {
        if !policy.allows(kind?) {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions);
        }
    }
    Ok(())
}

/// Invokes a signed `TransferChecked` CPI from a channel-owned token account.
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked_signed(
    from: &ChannelTokenAccountView<'_, Checked>,
    mint: &MintAccountView<'_, Checked>,
    to: &AnyTokenAccountsView<'_, Checked>,
    authority: &ChannelAccountView<'_, Checked>,
    amount: u64,
    decimals: u8,
    token_program: &TokenProgramAccountView<'_, Checked>,
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
        token_program: token_program.address(),
    }
    .invoke_signed(signers)
}

#[cfg(test)]
mod token_2022_extension_id_tests {
    use super::{ExtensionType, UNINITIALIZED};
    use spl_token_2022_interface::extension::ExtensionType as Upstream;

    #[test]
    fn mirrored_token_2022_extension_ids_match_upstream_wire_discriminants() {
        assert_eq!(UNINITIALIZED, Upstream::Uninitialized as u16);
        assert_eq!(
            ExtensionType::ImmutableOwner as u16,
            Upstream::ImmutableOwner as u16
        );
        assert_eq!(
            ExtensionType::MetadataPointer as u16,
            Upstream::MetadataPointer as u16
        );
        assert_eq!(
            ExtensionType::TokenMetadata as u16,
            Upstream::TokenMetadata as u16
        );
        assert_eq!(
            ExtensionType::GroupPointer as u16,
            Upstream::GroupPointer as u16
        );
        assert_eq!(
            ExtensionType::TokenGroup as u16,
            Upstream::TokenGroup as u16
        );
        assert_eq!(
            ExtensionType::GroupMemberPointer as u16,
            Upstream::GroupMemberPointer as u16
        );
        assert_eq!(
            ExtensionType::TokenGroupMember as u16,
            Upstream::TokenGroupMember as u16
        );
    }
}

#[cfg(test)]
mod tlv_tests {
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
    fn mint_policy_allows_metadata_and_group_extensions() {
        let p = MintExtensionPolicy;
        for ext in [
            ExtensionType::MetadataPointer,
            ExtensionType::TokenMetadata,
            ExtensionType::GroupPointer,
            ExtensionType::TokenGroup,
            ExtensionType::GroupMemberPointer,
            ExtensionType::TokenGroupMember,
        ] {
            assert!(p.allows(ext), "mint policy should allow {ext:?}");
        }
    }

    #[test]
    fn mint_policy_rejects_immutable_owner() {
        assert!(!MintExtensionPolicy.allows(ExtensionType::ImmutableOwner));
    }

    #[test]
    fn token_account_policy_allows_only_immutable_owner() {
        let p = TokenAccountExtensionPolicy;
        assert!(p.allows(ExtensionType::ImmutableOwner));
        for ext in [
            ExtensionType::MetadataPointer,
            ExtensionType::TokenMetadata,
            ExtensionType::GroupPointer,
            ExtensionType::TokenGroup,
            ExtensionType::GroupMemberPointer,
            ExtensionType::TokenGroupMember,
        ] {
            assert!(
                !p.allows(ext),
                "token-account policy must not allow {ext:?}"
            );
        }
    }

    #[test]
    fn extension_type_try_from_unknown_id_is_unsupported() {
        match ExtensionType::try_from(0xFFFFu16) {
            Err(PaymentChannelsError::UnsupportedTokenExtensions) => {}
            other => panic!("expected UnsupportedTokenExtensions, got {other:?}"),
        }
    }

    #[test]
    fn scan_accepts_empty_trailer() {
        assert!(scan_tlv_extensions(&[], &MintExtensionPolicy).is_ok());
        assert!(scan_tlv_extensions(&[], &TokenAccountExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_accepts_single_whitelisted_mint_extension() {
        let bytes = header(ExtensionType::MetadataPointer as u16, 0);
        assert!(scan_tlv_extensions(&bytes, &MintExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_accepts_chained_whitelisted_mint_extensions() {
        let h1 = header(ExtensionType::MetadataPointer as u16, 2);
        let h2 = header(ExtensionType::TokenMetadata as u16, 1);
        let bytes: [u8; 11] = [
            h1[0], h1[1], h1[2], h1[3], 0xAA, 0xBB, h2[0], h2[1], h2[2], h2[3], 0xCC,
        ];
        assert!(scan_tlv_extensions(&bytes, &MintExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_terminates_on_uninitialized_header() {
        let h1 = header(UNINITIALIZED, 0);
        let h2 = header(0xFFFF, 0);
        let bytes: [u8; 8] = [h1[0], h1[1], h1[2], h1[3], h2[0], h2[1], h2[2], h2[3]];
        assert!(scan_tlv_extensions(&bytes, &MintExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_terminates_on_uninitialized_sentinel_in_trailer() {
        // The first two zero bytes after the whitelisted entry decode to
        // UNINITIALIZED and end the walk; the remaining tail is unread.
        let h = header(ExtensionType::MetadataPointer as u16, 0);
        let mut bytes = [0u8; 4 + 64];
        bytes[..4].copy_from_slice(&h);
        assert!(scan_tlv_extensions(&bytes, &MintExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_rejects_truncated_header() {
        let bytes = [0x12, 0x00, 0x01];
        expect_err(
            scan_tlv_extensions(&bytes, &MintExtensionPolicy),
            PaymentChannelsError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_accepts_single_trailing_zero_byte() {
        // Below the 2-byte type field; mirrors upstream's graceful tail.
        assert!(scan_tlv_extensions(&[0x00], &MintExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_accepts_single_trailing_nonzero_byte() {
        assert!(scan_tlv_extensions(&[0xFF], &MintExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_rejects_two_trailing_bytes_as_whitelisted_type() {
        // type=METADATA_POINTER (whitelisted) but no length bytes follow.
        let bytes = [0x12, 0x00];
        expect_err(
            scan_tlv_extensions(&bytes, &MintExtensionPolicy),
            PaymentChannelsError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_rejects_two_trailing_bytes_as_forbidden_type() {
        // type=TransferFeeConfig (1) — must be rejected before the length check.
        let bytes = [0x01, 0x00];
        expect_err(
            scan_tlv_extensions(&bytes, &MintExtensionPolicy),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
    }

    #[test]
    fn scan_accepts_value_len_reaching_buffer_end() {
        let h = header(ExtensionType::MetadataPointer as u16, 4);
        let bytes: [u8; 8] = [h[0], h[1], h[2], h[3], 0xAA, 0xBB, 0xCC, 0xDD];
        assert!(scan_tlv_extensions(&bytes, &MintExtensionPolicy).is_ok());
    }

    #[test]
    fn scan_rejects_value_len_overflowing_remaining() {
        // declared value_len=8, only 4 payload bytes supplied
        let h = header(ExtensionType::MetadataPointer as u16, 8);
        let bytes: [u8; 8] = [h[0], h[1], h[2], h[3], 0, 0, 0, 0];
        expect_err(
            scan_tlv_extensions(&bytes, &MintExtensionPolicy),
            PaymentChannelsError::MalformedTokenAccountData,
        );
    }

    #[test]
    fn scan_rejects_non_whitelisted_type() {
        let bytes = header(0xFFFF, 0);
        expect_err(
            scan_tlv_extensions(&bytes, &MintExtensionPolicy),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
    }

    #[test]
    fn scan_rejects_mint_only_id_on_token_account() {
        let bytes = header(ExtensionType::MetadataPointer as u16, 0);
        expect_err(
            scan_tlv_extensions(&bytes, &TokenAccountExtensionPolicy),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
    }

    #[test]
    fn extension_tlv_iterator_yields_typed_kinds_and_advances_past_values() {
        let h1 = header(ExtensionType::MetadataPointer as u16, 2);
        let h2 = header(ExtensionType::TokenMetadata as u16, 1);
        let bytes: [u8; 11] = [
            h1[0], h1[1], h1[2], h1[3], 0xAA, 0xBB, h2[0], h2[1], h2[2], h2[3], 0xCC,
        ];
        let mut it = ExtensionTlv::new(&bytes);
        assert_eq!(
            it.next().expect("first").expect("ok"),
            ExtensionType::MetadataPointer,
        );
        assert_eq!(
            it.next().expect("second").expect("ok"),
            ExtensionType::TokenMetadata,
        );
        assert!(it.next().is_none());
    }
}
