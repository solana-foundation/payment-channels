use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::constants::{ATA_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID};
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
    pub(super) const START: usize = ACCOUNT_TYPE_OFFSET + size_of::<AccountType>();
    pub(super) const HEADER_LEN: usize = 4;
}

/// Token-2022 extension type ids accepted by this program. They are part of
/// the Token-2022 TLV wire format and intentionally mirrored here to keep this
/// program no-alloc/no-std. Asserted against upstream in the test module.
mod extension_id {
    pub(super) const UNINITIALIZED: u16 = 0;
    pub(super) const IMMUTABLE_OWNER: u16 = 7;
    pub(super) const METADATA_POINTER: u16 = 18;
    pub(super) const TOKEN_METADATA: u16 = 19;
    pub(super) const GROUP_POINTER: u16 = 20;
    pub(super) const TOKEN_GROUP: u16 = 21;
    pub(super) const GROUP_MEMBER_POINTER: u16 = 22;
    pub(super) const TOKEN_GROUP_MEMBER: u16 = 23;
}

/// Convenience constructor for the program's `ArithmeticOverflow` error,
/// shaped to fit `Option::ok_or_else` / `checked_*` call sites.
#[inline]
pub fn overflow() -> ProgramError {
    PaymentChannelsError::ArithmeticOverflow.into()
}

/// Derives the associated-token-account address for `(owner, mint, token_program)`
/// under the ATA program.
#[inline]
pub fn derive_ata(owner: &Address, mint: &Address, token_program: &Address) -> Address {
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}

/// Validates a mint account against `token_program` and returns its decimals.
///
/// SPL classic mints must be exactly `MINT_LEN`. Token-2022 mints are accepted
/// only when their TLV trailer carries extensions whitelisted as
/// transfer-amount-neutral (metadata/group pointers and payloads); anything
/// else — most importantly transfer fees, hooks, or confidential transfers —
/// is rejected so amount accounting cannot diverge from the literal `amount`.
pub fn validate_mint(mint: &AccountView, token_program: &Address) -> Result<u8, ProgramError> {
    let decimals = if *token_program == SPL_TOKEN_PROGRAM_ID {
        // pinocchio_token enforces owner == SPL classic + exact length.
        pinocchio_token::state::Mint::from_account_view(mint)
            .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
            .decimals()
    } else if *token_program == TOKEN_2022_PROGRAM_ID {
        // pinocchio_token_2022 enforces owner == Token-2022 and (when
        // extensions are present) the AccountType discriminator byte.
        pinocchio_token_2022::state::Mint::from_account_view(mint)
            .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
            .decimals()
    } else {
        return Err(PaymentChannelsError::InvalidTokenProgram.into());
    };

    if *token_program == TOKEN_2022_PROGRAM_ID {
        let data = mint.try_borrow()?;
        if data.len() > base_layout::MINT_LEN {
            // Upstream's `validate_account_type` checks the discriminator at
            // `Account::BASE_LEN` but doesn't enforce that the gap between the
            // mint base region and that offset is zero — guard against
            // smuggled bytes here, then walk the whitelisted TLV trailer.
            if !all_zero(&data[base_layout::MINT_LEN..tlv::ACCOUNT_TYPE_OFFSET]) {
                return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
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
    let (mint_addr, owner_addr, initialized) = if *token_program == SPL_TOKEN_PROGRAM_ID {
        let acc = pinocchio_token::state::Account::from_account_view(account)
            .map_err(|_| account_error)?;
        let initialized = matches!(
            acc.state(),
            pinocchio_token::state::AccountState::Initialized
        );
        (*acc.mint(), *acc.owner(), initialized)
    } else if *token_program == TOKEN_2022_PROGRAM_ID {
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

    if *token_program == TOKEN_2022_PROGRAM_ID {
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

/// Walks the Token-2022 TLV trailer and rejects any extension type not
/// whitelisted for the given account kind. Stops at the first uninitialized
/// or all-zero region, which marks unused TLV space.
fn scan_tlv_extensions(mut data: &[u8], is_mint: bool) -> ProgramResult {
    while !data.is_empty() {
        if all_zero(data) {
            return Ok(());
        }
        if data.len() < tlv::HEADER_LEN {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
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
            .ok_or_else(overflow)?;
        if next > data.len() {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
        }
        data = &data[next..];
    }

    Ok(())
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
