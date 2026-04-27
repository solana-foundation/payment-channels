#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};
use pinocchio_token_2022::state::{
    Account as TokenAccount, AccountState, AccountType, Mint as TokenMint,
};

use crate::constants::{
    ATA_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TREASURY_OWNER,
};
use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::{
    BPS_DENOMINATOR, DistributionEntry, MAX_DISTRIBUTION_RECIPIENTS,
};
use crate::state::channel::{CHANNEL_SEED, Channel, ChannelStatus};
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `distribute`.
pub const DISCRIMINATOR: u8 = 7;

/// Fixed preimage buffer size. `preimage_len` marks the active prefix; trailing
/// bytes are ignored by the hash rebuild.
pub const MAX_DISTRIBUTE_PREIMAGE: usize = 1 + MAX_DISTRIBUTION_RECIPIENTS * DistributionEntry::LEN;

/// SPL classic Mint byte length. Token-2022 mints with extensions are longer;
/// the distribute path parses Token-2022's TLV extension trailer explicitly so
/// only exact-accounting-safe extensions are accepted.
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

/// Token-2022 extension type ids accepted by this instruction. They are part
/// of the Token-2022 TLV wire format and intentionally mirrored here to keep
/// this program no-alloc/no-std.
const EXT_UNINITIALIZED: u16 = 0;
const EXT_IMMUTABLE_OWNER: u16 = 7;
const EXT_METADATA_POINTER: u16 = 18;
const EXT_TOKEN_METADATA: u16 = 19;
const EXT_GROUP_POINTER: u16 = 20;
const EXT_TOKEN_GROUP: u16 = 21;
const EXT_GROUP_MEMBER_POINTER: u16 = 22;
const EXT_TOKEN_GROUP_MEMBER: u16 = 23;

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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributeArgs {
    /// Active byte count inside [`Self::preimage`]. Bounds both the Blake3
    /// rehash input and the splits parser.
    #[cfg_attr(feature = "idl", codama(type = number(u16)))]
    preimage_len: [u8; 2],
    /// `num_recipients(1) || entries(n × DistributionEntry::LEN)`; rebuilt and
    /// hashed on-chain; digest must equal
    /// [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    #[cfg_attr(feature = "idl", codama(type = fixed_size(bytes, 1089)))]
    pub preimage: [u8; MAX_DISTRIBUTE_PREIMAGE],
}

impl DistributeArgs {
    pub const LEN: usize = size_of::<Self>();

    #[inline(always)]
    pub fn preimage_len(&self) -> u16 {
        u16::from_le_bytes(self.preimage_len)
    }

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for DistributeArgs {
    const LEN: usize = size_of::<Self>();
}

/// Fixed 7-slot head + dynamic recipient tail. Recipient ATAs sit in
/// `recipient_token_accounts` in the same order as `DistributionEntry`s in the
/// preimage; clients append them as remaining accounts.
pub struct DistributeAccounts<'a> {
    pub channel: &'a mut AccountView,
    pub payer: &'a mut AccountView,
    pub channel_token_account: &'a mut AccountView,
    pub payer_token_account: &'a mut AccountView,
    pub treasury_token_account: &'a mut AccountView,
    pub mint: &'a mut AccountView,
    pub token_program: &'a mut AccountView,
    pub recipient_token_accounts: &'a mut [AccountView],
}

impl<'a> TryFrom<&'a mut [AccountView]> for DistributeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [
            channel,
            payer,
            channel_token_account,
            payer_token_account,
            treasury_token_account,
            mint,
            token_program,
            recipient_rest @ ..,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            channel,
            payer,
            channel_token_account,
            payer_token_account,
            treasury_token_account,
            mint,
            token_program,
            recipient_token_accounts: recipient_rest,
        })
    }
}

/// Permissionless crank: verifies the committed preimage and pays
/// [`settled`](Channel::settled) `−` [`paid_out`](Channel::paid_out) across
/// recipients + payer's implicit share; residual goes to treasury. On
/// `FINALIZED`, also refunds the payer (if not already withdrawn) and
/// tombstones both the escrow ATA and the Channel PDA.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &DistributeArgs,
) -> ProgramResult {
    let accs = DistributeAccounts::try_from(accounts)?;

    // Capture immutable identity before the mut-borrow on channel data.
    let channel_address = *accs.channel.address();
    let now = Clock::get()?.unix_timestamp;

    // Owner / discriminator / version checks.
    let mut ch = Channel::from_account_mut(accs.channel)?;

    // Status gate.
    let status = ChannelStatus::try_from(ch.status)?;
    if !matches!(status, ChannelStatus::Open | ChannelStatus::Finalized) {
        return Err(PaymentChannelsError::ChannelNotClosable.into());
    }

    // Identity.
    if accs.payer.address() != &ch.payer {
        return Err(PaymentChannelsError::PayerAccountMismatch.into());
    }
    if accs.mint.address() != &ch.mint {
        return Err(PaymentChannelsError::MintAccountMismatch.into());
    }

    // Token program + extension-aware Mint layout.
    let tp = *accs.token_program.address();
    if tp != SPL_TOKEN_PROGRAM_ID && tp != TOKEN_2022_PROGRAM_ID {
        return Err(PaymentChannelsError::InvalidTokenProgram.into());
    }
    let decimals = validate_mint(accs.mint, &tp)?;

    // Re-derive PDA from the channel-stored salt; gated by bump cross-check.
    let salt = ch.salt();
    let (expected_pda, expected_bump) =
        Channel::find_pda(&ch.payer, &ch.payee, &ch.mint, &ch.authorized_signer, salt);
    if expected_pda != channel_address || expected_bump != ch.bump {
        return Err(PaymentChannelsError::ChannelAddressMismatch.into());
    }

    // ATA derivations.
    if *accs.channel_token_account.address() != derive_ata(&channel_address, &ch.mint, &tp) {
        return Err(PaymentChannelsError::InvalidChannelTokenAccount.into());
    }
    if *accs.payer_token_account.address() != derive_ata(&ch.payer, &ch.mint, &tp) {
        return Err(PaymentChannelsError::InvalidPayerTokenAccount.into());
    }
    if *accs.treasury_token_account.address() != derive_ata(&TREASURY_OWNER, &ch.mint, &tp) {
        return Err(PaymentChannelsError::TreasuryAddressMismatch.into());
    }
    validate_token_account(
        accs.channel_token_account,
        &ch.mint,
        &channel_address,
        &tp,
        PaymentChannelsError::InvalidChannelTokenAccount,
    )?;
    validate_token_account(
        accs.payer_token_account,
        &ch.mint,
        &ch.payer,
        &tp,
        PaymentChannelsError::InvalidPayerTokenAccount,
    )?;
    validate_token_account(
        accs.treasury_token_account,
        &ch.mint,
        &TREASURY_OWNER,
        &tp,
        PaymentChannelsError::TreasuryAddressMismatch,
    )?;

    // Preimage prefix.
    let preimage_len = args.preimage_len() as usize;
    if preimage_len == 0 || preimage_len > MAX_DISTRIBUTE_PREIMAGE {
        return Err(PaymentChannelsError::InvalidPreimageLength.into());
    }
    let n = args.preimage[0] as usize;
    if n == 0 || n > MAX_DISTRIBUTION_RECIPIENTS {
        return Err(PaymentChannelsError::InvalidRecipientCount.into());
    }
    let expected_len = 1usize
        .checked_add(n.checked_mul(DistributionEntry::LEN).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;
    if preimage_len != expected_len || accs.recipient_token_accounts.len() != n {
        return Err(PaymentChannelsError::InvalidPreimageLength.into());
    }

    // Blake3 rehash.
    let digest = crate::state::blake3(&args.preimage[..preimage_len]);
    if digest != ch.distribution_hash {
        return Err(PaymentChannelsError::InvalidDistributionHash.into());
    }

    // Transmute active entries. SAFETY: align-1 contract, length verified above.
    let entries: &[DistributionEntry] = unsafe {
        core::slice::from_raw_parts(args.preimage[1..].as_ptr().cast::<DistributionEntry>(), n)
    };

    // ATA match + bps sum.
    let mut bps_sum: u32 = 0;
    for (i, entry) in entries.iter().enumerate() {
        let expected = derive_ata(&entry.recipient, &ch.mint, &tp);
        if *accs.recipient_token_accounts[i].address() != expected {
            return Err(PaymentChannelsError::InvalidRecipientAccount.into());
        }
        if entry.bps() == 0 {
            return Err(PaymentChannelsError::InvalidSplitConfig.into());
        }
        validate_token_account(
            &accs.recipient_token_accounts[i],
            &ch.mint,
            &entry.recipient,
            &tp,
            PaymentChannelsError::InvalidRecipientAccount,
        )?;
        bps_sum = bps_sum
            .checked_add(entry.bps() as u32)
            .ok_or_else(overflow)?;
    }
    if bps_sum >= BPS_DENOMINATOR {
        return Err(PaymentChannelsError::InvalidSplitConfig.into());
    }

    // Pool = settled − paid_out.
    let pool = ch
        .settled()
        .checked_sub(ch.paid_out())
        .ok_or_else(overflow)?;
    if pool == 0 && status == ChannelStatus::Open {
        return Err(PaymentChannelsError::NothingToDistribute.into());
    }

    // Copy seed material into owned locals BEFORE mutating `ch`, so the
    // Signer's Seed refs don't alias the live `RefMut<Channel>`.
    let payer_bytes: [u8; 32] = *ch.payer.as_array();
    let payee_bytes: [u8; 32] = *ch.payee.as_array();
    let mint_bytes: [u8; 32] = *ch.mint.as_array();
    let signer_bytes: [u8; 32] = *ch.authorized_signer.as_array();
    let bump_arr: [u8; 1] = [ch.bump];
    let salt_le: [u8; 8] = salt.to_le_bytes();

    // Snapshot per-channel state we'll need after dropping `ch`.
    let deposit = ch.deposit();
    let settled = ch.settled();
    let payer_withdrawn_at = ch.payer_withdrawn_at();

    // Update paid_out while `ch` is still borrowed; doing it here leaves the
    // FINALIZED leg to run purely on the cloned snapshots without re-borrows.
    if pool > 0 {
        let new_paid_out = ch.paid_out().checked_add(pool).ok_or_else(overflow)?;
        ch.set_paid_out(new_paid_out);
    }

    // Release the data borrow so the tombstone path can close() the Channel.
    drop(ch);

    let signer_seeds: [Seed; 7] = [
        Seed::from(CHANNEL_SEED),
        Seed::from(&payer_bytes),
        Seed::from(&payee_bytes),
        Seed::from(&mint_bytes),
        Seed::from(&signer_bytes),
        Seed::from(&salt_le),
        Seed::from(&bump_arr),
    ];
    let signer = Signer::from(&signer_seeds);

    // Transfer splits + payer implicit share + treasury residual.
    let mut sum_paid: u64 = 0;
    if pool > 0 {
        for (i, entry) in entries.iter().enumerate() {
            let amount_i = share(pool, entry.bps() as u32)?;
            if amount_i > 0 {
                transfer_checked(
                    &tp,
                    accs.channel_token_account,
                    accs.mint,
                    &accs.recipient_token_accounts[i],
                    accs.channel,
                    amount_i,
                    decimals,
                    &signer,
                )?;
                sum_paid = sum_paid.checked_add(amount_i).ok_or_else(overflow)?;
            }
        }

        let payer_share = share(pool, BPS_DENOMINATOR - bps_sum)?;
        if payer_share > 0 {
            transfer_checked(
                &tp,
                accs.channel_token_account,
                accs.mint,
                accs.payer_token_account,
                accs.channel,
                payer_share,
                decimals,
                &signer,
            )?;
        }

        let transferred = sum_paid.checked_add(payer_share).ok_or_else(overflow)?;
        let residual = pool.checked_sub(transferred).ok_or_else(overflow)?;
        if residual > 0 {
            transfer_checked(
                &tp,
                accs.channel_token_account,
                accs.mint,
                accs.treasury_token_account,
                accs.channel,
                residual,
                decimals,
                &signer,
            )?;
        }
    }

    if status == ChannelStatus::Finalized {
        // Payer refund leg — one-shot, gated by payer_withdrawn_at.
        if payer_withdrawn_at == 0 {
            if deposit > settled {
                let refund = deposit - settled;
                transfer_checked(
                    &tp,
                    accs.channel_token_account,
                    accs.mint,
                    accs.payer_token_account,
                    accs.channel,
                    refund,
                    decimals,
                    &signer,
                )?;
            }
            let mut ch = Channel::from_account_mut(accs.channel)?;
            ch.set_payer_withdrawn_at(now);
            drop(ch);
        }

        // Close the escrow SPL account; rent flows to payer SOL account.
        close_token_account(
            &tp,
            accs.channel_token_account,
            accs.payer,
            accs.channel,
            &signer,
        )?;

        // Tombstone the Channel PDA: move rent lamports to payer, then close.
        let rent = accs.channel.lamports();
        let new_payer_bal = accs
            .payer
            .lamports()
            .checked_add(rent)
            .ok_or_else(overflow)?;
        accs.payer.set_lamports(new_payer_bal);
        accs.channel.set_lamports(0);
        accs.channel.close()?;
    }

    Ok(())
}

#[inline]
fn overflow() -> ProgramError {
    PaymentChannelsError::ArithmeticOverflow.into()
}

/// `floor(pool * bps / 10_000)` in u128 to avoid overflow.
#[inline]
fn share(pool: u64, bps: u32) -> Result<u64, ProgramError> {
    let prod = (pool as u128)
        .checked_mul(bps as u128)
        .ok_or_else(overflow)?;
    let q = prod / (BPS_DENOMINATOR as u128);
    Ok(q as u64)
}

#[inline]
fn derive_ata(owner: &Address, mint: &Address, token_program: &Address) -> Address {
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}

fn validate_mint(mint: &AccountView, token_program: &Address) -> Result<u8, ProgramError> {
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

fn validate_token_account(
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
fn transfer_checked(
    token_program: &Address,
    from: &AccountView,
    mint: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    amount: u64,
    decimals: u8,
    signer: &Signer,
) -> ProgramResult {
    // pinocchio-token-2022's TransferChecked dispatches via the `token_program`
    // field, so it works for both SPL Token and Token-2022. We validated the tp
    // address up front.
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
fn close_token_account(
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
