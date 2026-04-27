use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError};
use pinocchio_token_2022::state::{Account as TokenAccount, AccountType, Mint as TokenMint};

use crate::constants::{ATA_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID};
use crate::errors::PaymentChannelsError;

mod base_layout {
    use pinocchio_token_2022::state::{Account as TokenAccount, AccountState, Mint as TokenMint};

    /// SPL classic Mint byte length. Token-2022 mints with extensions are longer;
    /// Token-2022's TLV trailer is parsed explicitly so only exact-accounting-safe
    /// extensions are accepted.
    pub(super) const MINT_LEN: usize = TokenMint::BASE_LEN;

    /// SPL classic token account byte length. Token-2022 account extensions follow
    /// the base account region.
    pub(super) const TOKEN_ACCOUNT_LEN: usize = TokenAccount::BASE_LEN;

    /// Offset of `state: u8` within the base token account layout.
    pub(super) const STATE_OFFSET: usize = 108;
    pub(super) const INITIALIZED: u8 = AccountState::Initialized as u8;
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

/// Rejects any program id that is not SPL Token or Token-2022.
#[inline]
pub fn validate_token_program(token_program: &Address) -> ProgramResult {
    if *token_program != SPL_TOKEN_PROGRAM_ID && *token_program != TOKEN_2022_PROGRAM_ID {
        return Err(PaymentChannelsError::InvalidTokenProgram.into());
    }
    Ok(())
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
    if !mint.owned_by(token_program) {
        return Err(PaymentChannelsError::MintAccountMismatch.into());
    }

    let data = mint.try_borrow()?;
    if data.len() < base_layout::MINT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    // SAFETY: length checked above; TokenMint has alignment 1.
    let decimals = unsafe { TokenMint::from_bytes_unchecked(&data) }.decimals();

    if *token_program == SPL_TOKEN_PROGRAM_ID {
        if data.len() != base_layout::MINT_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        return Ok(decimals);
    }

    if data.len() == base_layout::MINT_LEN {
        return Ok(decimals);
    }
    validate_token_2022_header(&data, base_layout::MINT_LEN, AccountType::Mint)?;
    scan_tlv_extensions(&data[tlv::START..], true)?;
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
    if !account.owned_by(token_program) {
        return Err(account_error.into());
    }

    let data = account.try_borrow()?;
    if data.len() < base_layout::TOKEN_ACCOUNT_LEN {
        return Err(account_error.into());
    }
    // SAFETY: length checked above; TokenAccount has alignment 1.
    let token_account = unsafe { TokenAccount::from_bytes_unchecked(&data) };
    if token_account.mint() != expected_mint
        || token_account.owner() != expected_owner
        || data[base_layout::STATE_OFFSET] != base_layout::INITIALIZED
    {
        return Err(account_error.into());
    }

    if *token_program == SPL_TOKEN_PROGRAM_ID {
        if data.len() != base_layout::TOKEN_ACCOUNT_LEN {
            return Err(account_error.into());
        }
        return Ok(());
    }

    if data.len() == base_layout::TOKEN_ACCOUNT_LEN {
        return Ok(());
    }
    validate_token_2022_header(&data, base_layout::TOKEN_ACCOUNT_LEN, AccountType::Account)?;
    scan_tlv_extensions(&data[tlv::START..], false)
}

/// Verifies the Token-2022 padding region between the base layout and the TLV
/// trailer is zero and that the account-type discriminator byte matches the
/// expected kind (mint vs token account).
fn validate_token_2022_header(
    data: &[u8],
    base_len: usize,
    expected_account_type: AccountType,
) -> ProgramResult {
    if data.len() < tlv::START
        || !all_zero(&data[base_len..tlv::ACCOUNT_TYPE_OFFSET])
        || data[tlv::ACCOUNT_TYPE_OFFSET] != expected_account_type as u8
    {
        return Err(PaymentChannelsError::UnsupportedTokenExtensions.into());
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

/// Invokes `TransferChecked` on SPL Token or Token-2022 with a user-controlled
/// `authority`.
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

/// `TransferChecked` invoked under PDA `signer` — used when the program's
/// channel PDA is the source authority.
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

/// Invokes `CloseAccount` under PDA `signer`, sweeping rent lamports from
/// `account` to `destination` and zeroing the token account.
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
