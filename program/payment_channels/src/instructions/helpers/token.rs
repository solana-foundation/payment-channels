use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError};
use pinocchio_token_2022::instructions::TransferChecked;

use crate::errors::PaymentChannelsError;

mod base_layout {
    use pinocchio_token_2022::state::{Account as TokenAccount, Mint as TokenMint};

    /// SPL classic Mint byte length. Token-2022 mints with extensions are longer;
    /// Token-2022's TLV trailer is parsed explicitly so only exact-accounting-safe
    /// extensions are accepted.
    pub(super) const MINT_LEN: usize = TokenMint::BASE_LEN;

    /// SPL classic token account byte length. Token-2022 account extensions follow
    /// the base account region.
    pub(super) const TOKEN_ACCOUNT_LEN: usize = TokenAccount::BASE_LEN;
}

mod tlv {
    use core::mem::size_of;
    use pinocchio_token_2022::state::AccountType;

    /// Token-2022 writes an account-type byte at this shared offset before TLV
    /// extension data for both mints and token accounts.
    pub(super) const ACCOUNT_TYPE_OFFSET: usize = super::base_layout::TOKEN_ACCOUNT_LEN;
    /// First byte of the TLV trailer — immediately after the account-type
    /// discriminator byte.
    pub(super) const START: usize = ACCOUNT_TYPE_OFFSET + size_of::<AccountType>();
    /// TLV header layout: `u16 type | u16 length`.
    pub(super) const HEADER_LEN: usize = 4;
}

/// Token-2022 extension type ids accepted by this program. They are part of
/// the Token-2022 TLV wire format and intentionally mirrored here to keep this
/// program no-alloc/no-std. Asserted against upstream in the test module.
mod extension_id {
    /// Sentinel for an empty TLV slot — terminates the extension walk.
    pub(super) const UNINITIALIZED: u16 = 0;
    /// Token-account-only: locks the `owner` field after initialization.
    pub(super) const IMMUTABLE_OWNER: u16 = 7;
    /// Mint-only: pointer to off-chain or inline metadata; transfer-amount-neutral.
    pub(super) const METADATA_POINTER: u16 = 18;
    /// Mint-only: inline metadata payload paired with `METADATA_POINTER`.
    pub(super) const TOKEN_METADATA: u16 = 19;
    /// Mint-only: pointer to a token-group account; transfer-amount-neutral.
    pub(super) const GROUP_POINTER: u16 = 20;
    /// Mint-only: inline group payload paired with `GROUP_POINTER`.
    pub(super) const TOKEN_GROUP: u16 = 21;
    /// Mint-only: pointer to a group-member account; transfer-amount-neutral.
    pub(super) const GROUP_MEMBER_POINTER: u16 = 22;
    /// Mint-only: inline group-member payload paired with `GROUP_MEMBER_POINTER`.
    pub(super) const TOKEN_GROUP_MEMBER: u16 = 23;
}

/// Derives the associated-token-account address for `(owner, mint, token_program)`
/// under the ATA program.
#[inline]
pub fn derive_ata(owner: &Address, mint: &Address, token_program: &Address) -> Address {
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &pinocchio_associated_token_account::ID,
    )
    .0
}

/// Validates only the associated-token-account address for a role.
fn validate_ata_address(
    account: &AccountView,
    expected_owner: &Address,
    expected_mint: &Address,
    token_program: &Address,
    account_error: PaymentChannelsError,
) -> ProgramResult {
    if *account.address() != derive_ata(expected_owner, expected_mint, token_program) {
        return Err(account_error.into());
    }
    Ok(())
}

/// Validates that `account` is the expected ATA for `expected_owner` and then
/// validates the underlying token-account layout and state.
pub fn validate_ata_token_account(
    account: &AccountView,
    expected_owner: &Address,
    expected_mint: &Address,
    token_program: &Address,
    account_error: PaymentChannelsError,
) -> ProgramResult {
    validate_ata_address(
        account,
        expected_owner,
        expected_mint,
        token_program,
        account_error,
    )?;
    validate_token_account(
        account,
        expected_mint,
        expected_owner,
        token_program,
        account_error,
    )
}

/// Validates a mint account against `token_program` and returns its decimals.
///
/// SPL classic mints must be exactly `MINT_LEN`. Token-2022 mints are accepted
/// only when their TLV trailer carries extensions whitelisted as
/// transfer-amount-neutral (metadata/group pointers and payloads); anything
/// else — most importantly transfer fees, hooks, or confidential transfers —
/// is rejected so amount accounting cannot diverge from the literal `amount`.
pub fn validate_mint(mint: &AccountView, token_program: &Address) -> Result<u8, ProgramError> {
    let decimals = if *token_program == pinocchio_token::ID {
        // pinocchio_token enforces owner == SPL classic + exact length.
        pinocchio_token::state::Mint::from_account_view(mint)
            .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
            .decimals()
    } else if *token_program == pinocchio_token_2022::ID {
        // pinocchio_token_2022 enforces owner == Token-2022 and (when
        // extensions are present) the AccountType discriminator byte.
        pinocchio_token_2022::state::Mint::from_account_view(mint)
            .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
            .decimals()
    } else {
        return Err(PaymentChannelsError::InvalidTokenProgram.into());
    };

    if *token_program == pinocchio_token_2022::ID {
        let data = mint.try_borrow()?;
        if data.len() > base_layout::MINT_LEN {
            // Upstream's `validate_account_type` checks the discriminator at
            // `Account::BASE_LEN` but doesn't enforce that the gap between the
            // mint base region and that offset is zero — guard against
            // smuggled bytes here, then walk the whitelisted TLV trailer.
            if !all_zero(&data[base_layout::MINT_LEN..tlv::ACCOUNT_TYPE_OFFSET]) {
                return Err(PaymentChannelsError::MalformedTokenAccountData.into());
            }
            scan_tlv_extensions(&data[tlv::START..], true)?;
        }
    }

    Ok(decimals)
}

/// Validates that `account` is a token account owned by `token_program`, holds
/// `expected_mint`, is owned by `expected_owner`, and is in the `Initialized`
/// state. Token-2022 accounts may carry only the `ImmutableOwner` extension.
/// Any failure surfaces as `account_error` so callers can attribute the fault
/// to the specific role (source vault, recipient ATA, etc.).
pub fn validate_token_account(
    account: &AccountView,
    expected_mint: &Address,
    expected_owner: &Address,
    token_program: &Address,
    account_error: PaymentChannelsError,
) -> ProgramResult {
    let (mint_addr, owner_addr, initialized) = if *token_program == pinocchio_token::ID {
        let acc = pinocchio_token::state::Account::from_account_view(account)
            .map_err(|_| account_error)?;
        let initialized = matches!(
            acc.state(),
            pinocchio_token::state::AccountState::Initialized
        );
        (*acc.mint(), *acc.owner(), initialized)
    } else if *token_program == pinocchio_token_2022::ID {
        let acc = pinocchio_token_2022::state::Account::from_account_view(account)
            .map_err(|_| account_error)?;
        let initialized = matches!(
            acc.state(),
            pinocchio_token_2022::state::AccountState::Initialized
        );
        (*acc.mint(), *acc.owner(), initialized)
    } else {
        return Err(PaymentChannelsError::InvalidTokenProgram.into());
    };

    if &mint_addr != expected_mint || &owner_addr != expected_owner || !initialized {
        return Err(account_error.into());
    }

    if *token_program == pinocchio_token_2022::ID {
        let data = account.try_borrow()?;
        if data.len() > base_layout::TOKEN_ACCOUNT_LEN {
            // Token-account base layout already aligns with the AccountType
            // discriminator offset, so there's no padding to police — go
            // straight to the whitelisted TLV walk.
            scan_tlv_extensions(&data[tlv::START..], false)?;
        }
    }

    Ok(())
}

/// Returns the raw token amount from an already-validated token account.
pub fn token_account_amount(
    account: &AccountView,
    token_program: &Address,
    account_error: PaymentChannelsError,
) -> Result<u64, ProgramError> {
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
        Err(PaymentChannelsError::InvalidTokenProgram.into())
    }
}

/// Walks the Token-2022 TLV trailer and rejects any extension type not
/// whitelisted for the given account kind. Stops at the first uninitialized
/// or all-zero region, which marks unused TLV space.
fn scan_tlv_extensions(mut data: &[u8], is_mint: bool) -> ProgramResult {
    while !data.is_empty() {
        if all_zero(data) {
            return Ok(());
        }
        if data.len() < tlv::HEADER_LEN {
            return Err(PaymentChannelsError::MalformedTokenAccountData.into());
        }

        let extension_type = u16::from_le_bytes([data[0], data[1]]);
        if extension_type == extension_id::UNINITIALIZED {
            return Ok(());
        }

        if !extension_allowed(extension_type, is_mint) {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
        }

        let value_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let next = tlv::HEADER_LEN
            .checked_add(value_len)
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
        if next > data.len() {
            return Err(PaymentChannelsError::MalformedTokenAccountData.into());
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

/// True iff every byte in `bytes` is zero.
fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
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

    fn expect_err(result: ProgramResult, expected: PaymentChannelsError) {
        match result {
            Ok(()) => panic!("expected error, got Ok"),
            Err(ProgramError::Custom(c)) => assert_eq!(c, expected as u32),
            Err(e) => panic!("expected custom error, got {e:?}"),
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
    fn scan_terminates_on_uninitialized_header() {
        // UNINITIALIZED type byte short-circuits the walk, leaving the fake
        // out-of-whitelist tail unread.
        let h1 = header(UNINITIALIZED, 0);
        let h2 = header(0xFFFF, 0);
        let bytes: [u8; 8] = [h1[0], h1[1], h1[2], h1[3], h2[0], h2[1], h2[2], h2[3]];
        assert!(scan_tlv_extensions(&bytes, true).is_ok());
    }

    #[test]
    fn scan_treats_trailing_zero_region_as_terminator() {
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
