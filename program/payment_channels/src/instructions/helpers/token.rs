use core::mem::size_of;

use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError};
use pinocchio_token_2022::state::{
    Account as TokenAccount, AccountState, AccountType, Mint as TokenMint,
};

use crate::constants::{ATA_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID};
use crate::errors::PaymentChannelsError;

/// SPL classic Mint byte length. Token-2022 mints with extensions are longer;
/// Token-2022's TLV trailer is parsed explicitly so only exact-accounting-safe
/// extensions are accepted.
const BASE_MINT_LEN: usize = TokenMint::BASE_LEN;

/// SPL classic token account byte length. Token-2022 account extensions follow
/// the base account region.
const BASE_TOKEN_ACCOUNT_LEN: usize = TokenAccount::BASE_LEN;

/// Token-2022 writes an account-type byte at this shared offset before TLV
/// extension data for both mints and token accounts.
const TOKEN_2022_ACCOUNT_TYPE_OFFSET: usize = BASE_TOKEN_ACCOUNT_LEN;
const TOKEN_2022_TLV_START: usize = TOKEN_2022_ACCOUNT_TYPE_OFFSET + size_of::<AccountType>();
const TOKEN_2022_TLV_HEADER_LEN: usize = 4;

/// Offset of `state: u8` within the base token account layout.
const TOKEN_ACCOUNT_STATE_OFFSET: usize = 108;
const TOKEN_ACCOUNT_INITIALIZED: u8 = AccountState::Initialized as u8;

/// Token-2022 extension type ids accepted by this program. They are part of
/// the Token-2022 TLV wire format and intentionally mirrored here to keep this
/// program no-alloc/no-std.
const EXT_UNINITIALIZED: u16 = 0;
const EXT_IMMUTABLE_OWNER: u16 = 7;
const EXT_METADATA_POINTER: u16 = 18;
const EXT_TOKEN_METADATA: u16 = 19;
const EXT_GROUP_POINTER: u16 = 20;
const EXT_TOKEN_GROUP: u16 = 21;
const EXT_GROUP_MEMBER_POINTER: u16 = 22;
const EXT_TOKEN_GROUP_MEMBER: u16 = 23;

#[inline]
pub fn overflow() -> ProgramError {
    PaymentChannelsError::ArithmeticOverflow.into()
}

#[inline]
pub fn validate_token_program(token_program: &Address) -> ProgramResult {
    if *token_program != SPL_TOKEN_PROGRAM_ID && *token_program != TOKEN_2022_PROGRAM_ID {
        return Err(PaymentChannelsError::InvalidTokenProgram.into());
    }
    Ok(())
}

#[inline]
pub fn derive_ata(owner: &Address, mint: &Address, token_program: &Address) -> Address {
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}

pub fn validate_mint(mint: &AccountView, token_program: &Address) -> Result<u8, ProgramError> {
    if !mint.owned_by(token_program) {
        return Err(PaymentChannelsError::MintAccountMismatch.into());
    }

    let data = mint.try_borrow()?;
    if data.len() < BASE_MINT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    // SAFETY: length checked above; TokenMint has alignment 1.
    let decimals = unsafe { TokenMint::from_bytes_unchecked(&data) }.decimals();

    if *token_program == SPL_TOKEN_PROGRAM_ID {
        if data.len() != BASE_MINT_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        return Ok(decimals);
    }

    if data.len() == BASE_MINT_LEN {
        return Ok(decimals);
    }
    validate_token_2022_header(&data, BASE_MINT_LEN, AccountType::Mint)?;
    scan_tlv_extensions(&data[TOKEN_2022_TLV_START..], true)?;
    Ok(decimals)
}

pub fn validate_token_account(
    account: &AccountView,
    expected_mint: &Address,
    expected_owner: &Address,
    token_program: &Address,
    account_error: PaymentChannelsError,
) -> ProgramResult {
    if !account.owned_by(token_program) {
        return Err(account_error.into());
    }

    let data = account.try_borrow()?;
    if data.len() < BASE_TOKEN_ACCOUNT_LEN {
        return Err(account_error.into());
    }
    // SAFETY: length checked above; TokenAccount has alignment 1.
    let token_account = unsafe { TokenAccount::from_bytes_unchecked(&data) };
    if token_account.mint() != expected_mint
        || token_account.owner() != expected_owner
        || data[TOKEN_ACCOUNT_STATE_OFFSET] != TOKEN_ACCOUNT_INITIALIZED
    {
        return Err(account_error.into());
    }

    if *token_program == SPL_TOKEN_PROGRAM_ID {
        if data.len() != BASE_TOKEN_ACCOUNT_LEN {
            return Err(account_error.into());
        }
        return Ok(());
    }

    if data.len() == BASE_TOKEN_ACCOUNT_LEN {
        return Ok(());
    }
    validate_token_2022_header(&data, BASE_TOKEN_ACCOUNT_LEN, AccountType::Account)?;
    scan_tlv_extensions(&data[TOKEN_2022_TLV_START..], false)
}

fn validate_token_2022_header(
    data: &[u8],
    base_len: usize,
    expected_account_type: AccountType,
) -> ProgramResult {
    if data.len() < TOKEN_2022_TLV_START
        || !all_zero(&data[base_len..TOKEN_2022_ACCOUNT_TYPE_OFFSET])
        || data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] != expected_account_type as u8
    {
        return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
    }
    Ok(())
}

fn scan_tlv_extensions(mut data: &[u8], is_mint: bool) -> ProgramResult {
    while !data.is_empty() {
        if all_zero(data) {
            return Ok(());
        }
        if data.len() < TOKEN_2022_TLV_HEADER_LEN {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
        }

        let extension_type = u16::from_le_bytes([data[0], data[1]]);
        if extension_type == EXT_UNINITIALIZED {
            return Ok(());
        }

        if !extension_allowed(extension_type, is_mint) {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
        }

        let value_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let next = TOKEN_2022_TLV_HEADER_LEN
            .checked_add(value_len)
            .ok_or_else(overflow)?;
        if next > data.len() {
            return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
        }
        data = &data[next..];
    }

    Ok(())
}

fn extension_allowed(extension_type: u16, is_mint: bool) -> bool {
    if is_mint {
        matches!(
            extension_type,
            EXT_METADATA_POINTER
                | EXT_TOKEN_METADATA
                | EXT_GROUP_POINTER
                | EXT_TOKEN_GROUP
                | EXT_GROUP_MEMBER_POINTER
                | EXT_TOKEN_GROUP_MEMBER
        )
    } else {
        extension_type == EXT_IMMUTABLE_OWNER
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

#[allow(clippy::too_many_arguments)]
#[inline]
pub fn transfer_checked(
    token_program: &Address,
    from: &AccountView,
    mint: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    amount: u64,
    decimals: u8,
) -> ProgramResult {
    pinocchio_token_2022::instructions::TransferChecked {
        from,
        mint,
        to,
        authority,
        amount,
        decimals,
        token_program,
    }
    .invoke()
}

#[allow(clippy::too_many_arguments)]
#[inline]
pub fn transfer_checked_signed(
    token_program: &Address,
    from: &AccountView,
    mint: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    amount: u64,
    decimals: u8,
    signer: &Signer,
) -> ProgramResult {
    pinocchio_token_2022::instructions::TransferChecked {
        from,
        mint,
        to,
        authority,
        amount,
        decimals,
        token_program,
    }
    .invoke_signed(core::slice::from_ref(signer))
}

#[inline]
pub fn close_token_account(
    token_program: &Address,
    account: &AccountView,
    destination: &AccountView,
    authority: &AccountView,
    signer: &Signer,
) -> ProgramResult {
    pinocchio_token_2022::instructions::CloseAccount {
        account,
        destination,
        authority,
        token_program,
    }
    .invoke_signed(core::slice::from_ref(signer))
}

#[cfg(test)]
mod token_2022_extension_id_tests {
    use super::*;
    use spl_token_2022_interface::extension::ExtensionType;

    #[test]
    fn mirrored_token_2022_extension_ids_match_upstream_wire_discriminants() {
        assert_eq!(EXT_UNINITIALIZED, ExtensionType::Uninitialized as u16);
        assert_eq!(EXT_IMMUTABLE_OWNER, ExtensionType::ImmutableOwner as u16);
        assert_eq!(EXT_METADATA_POINTER, ExtensionType::MetadataPointer as u16);
        assert_eq!(EXT_TOKEN_METADATA, ExtensionType::TokenMetadata as u16);
        assert_eq!(EXT_GROUP_POINTER, ExtensionType::GroupPointer as u16);
        assert_eq!(EXT_TOKEN_GROUP, ExtensionType::TokenGroup as u16);
        assert_eq!(
            EXT_GROUP_MEMBER_POINTER,
            ExtensionType::GroupMemberPointer as u16
        );
        assert_eq!(
            EXT_TOKEN_GROUP_MEMBER,
            ExtensionType::TokenGroupMember as u16
        );
    }
}
