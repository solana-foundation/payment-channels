#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::Signer,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};
use pinocchio_token_2022::instructions::{CloseAccount, TransferChecked};

use crate::constants::TREASURY_OWNER;
use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::{
    BPS_DENOMINATOR, DistributionRecipients, channel_signer_seeds, derive_ata, validate_mint,
    validate_token_account,
};
use crate::state::channel::{Channel, ChannelStatus};
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `distribute`.
pub const DISCRIMINATOR: u8 = 7;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributeArgs {
    /// Reveal of the plan committed at `open`. Rehashed on-chain; digest must
    /// equal [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    pub recipients: DistributionRecipients,
}

impl DistributeArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for DistributeArgs {
    const LEN: usize = size_of::<Self>();
}

/// Fixed 8-slot head + dynamic recipient tail. Recipient ATAs sit in
/// `recipient_token_accounts` in the same order as the active entries in
/// `DistributeArgs::recipients`; clients append them as remaining accounts.
pub struct DistributeAccounts<'a> {
    pub channel: &'a mut AccountView,
    pub payer: &'a mut AccountView,
    /// Escrow; source for all splits, the payee implicit remainder, and the
    /// FINALIZED payer refund.
    pub channel_token_account: &'a mut AccountView,
    /// Payer refund destination. Used **only** by the FINALIZED branch when
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0` and
    /// `deposit > settled`; the implicit remainder of `pool` no longer
    /// touches this account.
    pub payer_token_account: &'a mut AccountView,
    /// Implicit-remainder destination: receives
    /// `floor(pool * (10_000 − Σ bps) / 10_000)` on every `distribute` where
    /// `pool > 0`. Always validated even when `Σ bps == 10_000` (transfer
    /// is then a no-op).
    pub payee_token_account: &'a mut AccountView,
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
            payee_token_account,
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
            payee_token_account,
            treasury_token_account,
            mint,
            token_program,
            recipient_token_accounts: recipient_rest,
        })
    }
}

/// Permissionless crank: verifies the committed preimage and pays
/// [`settled`](Channel::settled) `−` [`paid_out`](Channel::paid_out) across
/// recipients + payee's implicit remainder share; residual goes to treasury.
/// On `FINALIZED`, also refunds the payer the unspent
/// [`deposit`](Channel::deposit) `−` [`settled`](Channel::settled) headroom
/// (if not already withdrawn) and tombstones both the escrow ATA and the
/// Channel PDA.
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
        return Err(PaymentChannelsError::ChannelNotDistributable.into());
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
    let decimals = validate_mint(accs.mint, &tp)?;

    // Re-derive channel PDA
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
    if *accs.payee_token_account.address() != derive_ata(&ch.payee, &ch.mint, &tp) {
        return Err(PaymentChannelsError::InvalidPayeeTokenAccount.into());
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
        accs.payee_token_account,
        &ch.mint,
        &ch.payee,
        &tp,
        PaymentChannelsError::InvalidPayeeTokenAccount,
    )?;
    validate_token_account(
        accs.treasury_token_account,
        &ch.mint,
        &TREASURY_OWNER,
        &tp,
        PaymentChannelsError::TreasuryAddressMismatch,
    )?;

    // Bounds-check count + recipient-tail length before hashing. validate()
    // guards preimage_hash() against an out-of-range slice on count > 32.
    let n = args.recipients.validate()?;
    if accs.recipient_token_accounts.len() != n {
        return Err(PaymentChannelsError::InvalidRecipientCount.into());
    }

    // Blake3 rehash.
    let digest = args.recipients.preimage_hash();
    if digest != ch.distribution_hash {
        return Err(PaymentChannelsError::InvalidDistributionHash.into());
    }

    let entries = &args.recipients.entries[..n];

    // ATA match + bps sum. Split config validity is enforced at `open`; here
    // the sum is rebuilt only to calculate the payee's implicit remainder.
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
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    }
    let payee_bps = BPS_DENOMINATOR
        .checked_sub(bps_sum)
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;

    // Pool = settled − paid_out.
    let pool = ch
        .settled()
        .checked_sub(ch.paid_out())
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
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
    // FINALIZED branch to run purely on the cloned snapshots without re-borrows.
    if pool > 0 {
        let new_paid_out = ch
            .paid_out()
            .checked_add(pool)
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
        ch.set_paid_out(new_paid_out);
    }

    // Release the data borrow so the tombstone path can close() the Channel.
    drop(ch);

    let signer_seeds = channel_signer_seeds(
        &payer_bytes,
        &payee_bytes,
        &mint_bytes,
        &signer_bytes,
        &salt_le,
        &bump_arr,
    );
    let signer = Signer::from(&signer_seeds);

    // Transfer splits + payee implicit share + treasury residual.
    let mut sum_paid: u64 = 0;
    if pool > 0 {
        for (i, entry) in entries.iter().enumerate() {
            let amount_i = share(pool, entry.bps() as u32)?;
            if amount_i > 0 {
                TransferChecked {
                    from: accs.channel_token_account,
                    mint: accs.mint,
                    to: &accs.recipient_token_accounts[i],
                    authority: accs.channel,
                    amount: amount_i,
                    decimals,
                    token_program: &tp,
                }
                .invoke_signed(core::slice::from_ref(&signer))?;
                sum_paid = sum_paid
                    .checked_add(amount_i)
                    .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
            }
        }

        let payee_share = share(pool, payee_bps)?;
        if payee_share > 0 {
            TransferChecked {
                from: accs.channel_token_account,
                mint: accs.mint,
                to: accs.payee_token_account,
                authority: accs.channel,
                amount: payee_share,
                decimals,
                token_program: &tp,
            }
            .invoke_signed(core::slice::from_ref(&signer))?;
        }

        let transferred = sum_paid
            .checked_add(payee_share)
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
        let residual = pool
            .checked_sub(transferred)
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
        if residual > 0 {
            TransferChecked {
                from: accs.channel_token_account,
                mint: accs.mint,
                to: accs.treasury_token_account,
                authority: accs.channel,
                amount: residual,
                decimals,
                token_program: &tp,
            }
            .invoke_signed(core::slice::from_ref(&signer))?;
        }
    }

    if status == ChannelStatus::Finalized {
        // Payer refund branch — one-shot, gated by payer_withdrawn_at.
        if payer_withdrawn_at == 0 {
            if deposit > settled {
                let refund = deposit - settled;
                TransferChecked {
                    from: accs.channel_token_account,
                    mint: accs.mint,
                    to: accs.payer_token_account,
                    authority: accs.channel,
                    amount: refund,
                    decimals,
                    token_program: &tp,
                }
                .invoke_signed(core::slice::from_ref(&signer))?;
            }
            let mut ch = Channel::from_account_mut(accs.channel)?;
            ch.set_payer_withdrawn_at(now);
            drop(ch);
        }

        // Close the escrow SPL account; rent flows to payer SOL account.
        CloseAccount {
            account: accs.channel_token_account,
            destination: accs.payer,
            authority: accs.channel,
            token_program: &tp,
        }
        .invoke_signed(core::slice::from_ref(&signer))?;

        // Tombstone the Channel PDA: move rent lamports to payer, then close.
        let rent = accs.channel.lamports();
        let new_payer_bal = accs
            .payer
            .lamports()
            .checked_add(rent)
            .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
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
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    let q = prod / (BPS_DENOMINATOR as u128);
    Ok(q as u64)
}
