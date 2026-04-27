#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::constants::TREASURY_OWNER;
use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::{
    BPS_DENOMINATOR, DistributionEntry, MAX_DISTRIBUTION_RECIPIENTS, close_token_account,
    derive_ata, overflow, transfer_checked_signed, validate_mint, validate_token_account,
    validate_token_program,
};
use crate::state::channel::{CHANNEL_SEED, Channel, ChannelStatus};
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `distribute`.
pub const DISCRIMINATOR: u8 = 7;

/// Fixed preimage buffer size. `preimage_len` marks the active prefix; trailing
/// bytes are ignored by the hash rebuild.
pub const MAX_DISTRIBUTE_PREIMAGE: usize = 1 + MAX_DISTRIBUTION_RECIPIENTS * DistributionEntry::LEN;

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
    validate_token_program(&tp)?;
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

    // ATA match + bps sum. Split config validity is enforced at `open`; here
    // the sum is rebuilt only to calculate the payer's implicit remainder.
    let mut bps_sum: u32 = 0;
    for (i, entry) in entries.iter().enumerate() {
        let expected = derive_ata(&entry.recipient, &ch.mint, &tp);
        if *accs.recipient_token_accounts[i].address() != expected {
            return Err(PaymentChannelsError::InvalidRecipientAccount.into());
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
    let payer_bps = BPS_DENOMINATOR.checked_sub(bps_sum).ok_or_else(overflow)?;

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
                transfer_checked_signed(
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

        let payer_share = share(pool, payer_bps)?;
        if payer_share > 0 {
            transfer_checked_signed(
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
            transfer_checked_signed(
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
                transfer_checked_signed(
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

/// `floor(pool * bps / 10_000)` in u128 to avoid overflow.
#[inline]
fn share(pool: u64, bps: u32) -> Result<u64, ProgramError> {
    let prod = (pool as u128)
        .checked_mul(bps as u128)
        .ok_or_else(overflow)?;
    let q = prod / (BPS_DENOMINATOR as u128);
    Ok(q as u64)
}
