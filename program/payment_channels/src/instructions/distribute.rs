#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::Signer,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};
use pinocchio_token_2022::instructions::CloseAccount;

use crate::constants::TREASURY_OWNER;
use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::{
    DistributionEntry, DistributionRecipients, channel_signer_seeds, floor_bps_share,
    token_account_amount, transfer_checked_signed, validate_ata_token_account, validate_mint,
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
    /// Channel PDA whose accounting state is advanced and, on FINALIZED,
    /// tombstoned after all token movement is complete.
    pub channel: &'a mut AccountView,
    /// Original payer wallet. Receives SOL rent on FINALIZED cleanup and must
    /// match [`Channel::payer`](crate::Channel::payer).
    pub payer: &'a mut AccountView,
    /// Escrow; source for all splits, the payee implicit remainder, and the
    /// FINALIZED payer refund.
    pub channel_token_account: &'a mut AccountView,
    /// Payer refund destination. Used **only** by the FINALIZED branch when
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0` and
    /// `deposit > settled`.
    pub payer_token_account: &'a mut AccountView,
    /// Implicit-remainder destination: receives
    /// `floor(pool * (10_000 − Σ bps) / 10_000)` whenever `payee_bps > 0`.
    /// Always supplied because the accounts schema is fixed; the transfer
    /// call is skipped at the call site when `Σ bps == 10_000`.
    pub payee_token_account: &'a mut AccountView,
    /// Treasury destination: receives flooring residual when the channel is
    /// finalized and ready to close.
    pub treasury_token_account: &'a mut AccountView,
    /// Mint bound into the channel and used for every token transfer.
    pub mint: &'a mut AccountView,
    /// SPL Token or Token-2022 program used by the escrow and payout ATAs.
    pub token_program: &'a mut AccountView,
    /// Dynamic recipient ATA tail, ordered exactly like the active entries in
    /// the revealed distribution plan.
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
/// recipients + payee's implicit remainder share. From `OPEN`, flooring
/// residual stays in escrow. From `FINALIZED`, residual is swept to treasury.
/// On `FINALIZED`, also refunds the payer the unspent
/// [`deposit`](Channel::deposit) `−` [`settled`](Channel::settled) headroom
/// (if not already withdrawn) and tombstones both the escrow ATA and the
/// Channel PDA.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &DistributeArgs,
) -> ProgramResult {
    let mut accs = DistributeAccounts::try_from(accounts)?;

    // Load and validate the channel identity before inspecting token accounts.
    // The channel address is captured first because `ch` borrows its data.
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

    let salt = ch.salt();

    // Validate the fixed token accounts first.
    validate_ata_token_account(
        accs.channel_token_account,
        &channel_address,
        &ch.mint,
        &tp,
        PaymentChannelsError::InvalidChannelTokenAccount,
    )?;
    validate_ata_token_account(
        accs.payer_token_account,
        &ch.payer,
        &ch.mint,
        &tp,
        PaymentChannelsError::InvalidPayerTokenAccount,
    )?;
    validate_ata_token_account(
        accs.payee_token_account,
        &ch.payee,
        &ch.mint,
        &tp,
        PaymentChannelsError::InvalidPayeeTokenAccount,
    )?;
    validate_ata_token_account(
        accs.treasury_token_account,
        &TREASURY_OWNER,
        &ch.mint,
        &tp,
        PaymentChannelsError::TreasuryAddressMismatch,
    )?;

    // Hash equality is the sole plan-level gate: a matching digest proves
    // the revealed plan is byte-identical to the one open committed, which
    // open already validated. Anything below this point trusts the plan.
    let digest = args.recipients.preimage_hash();
    if digest != ch.distribution_hash {
        return Err(PaymentChannelsError::InvalidDistributionHash.into());
    }

    let distribution = args.recipients.view_unchecked();

    if accs.recipient_token_accounts.len() != distribution.entries.len() {
        return Err(PaymentChannelsError::RecipientAccountCountMismatch.into());
    }

    for (entry, recipient_token_account) in distribution
        .entries
        .iter()
        .zip(accs.recipient_token_accounts.iter())
    {
        validate_ata_token_account(
            recipient_token_account,
            &entry.recipient,
            &ch.mint,
            &tp,
            PaymentChannelsError::InvalidRecipientAccount,
        )?;
    }

    // Pool = settled − paid_out.
    let pool = ch
        .settled()
        .checked_sub(ch.paid_out())
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    if pool == 0 && status == ChannelStatus::Open {
        return Err(PaymentChannelsError::NothingToDistribute.into());
    }

    // Copy PDA seed bytes before dropping `ch`; signer seeds borrow these
    // arrays and must stay alive for every CPI below.
    let payer_bytes: [u8; 32] = *ch.payer.as_array();
    let payee_bytes: [u8; 32] = *ch.payee.as_array();
    let mint_bytes: [u8; 32] = *ch.mint.as_array();
    let signer_bytes: [u8; 32] = *ch.authorized_signer.as_array();
    let salt_bytes: [u8; 8] = salt.to_le_bytes();
    let bump_byte: [u8; 1] = [ch.bump];

    // Snapshot accounting fields, then update channel state before any CPI.
    // Runtime rollback protects these writes if a later transfer or close fails.
    let deposit = ch.deposit();
    let settled = ch.settled();
    let payer_withdrawn_at = ch.payer_withdrawn_at();

    if pool > 0 {
        ch.set_paid_out(settled);
    }
    if status == ChannelStatus::Finalized && payer_withdrawn_at == 0 {
        ch.set_payer_withdrawn_at(now);
    }

    // Release the data borrow so the tombstone path can close() the Channel.
    drop(ch);

    let signer_seeds = channel_signer_seeds(
        &payer_bytes,
        &payee_bytes,
        &mint_bytes,
        &signer_bytes,
        &salt_bytes,
        &bump_byte,
    );
    let signers = [Signer::from(&signer_seeds)];

    transfer_pool(
        &mut accs,
        distribution.entries,
        distribution.payee_bps,
        pool,
        decimals,
        &tp,
        &signers,
    )?;

    if status == ChannelStatus::Finalized {
        // Payer refund branch — one-shot, gated by payer_withdrawn_at.
        if payer_withdrawn_at == 0 && deposit > settled {
            transfer_checked_signed(
                accs.channel_token_account,
                accs.mint,
                accs.payer_token_account,
                accs.channel,
                deposit - settled,
                decimals,
                &tp,
                &signers,
            )?;
        }
        sweep_finalized_residual(&mut accs, decimals, &tp, &signers)?;
        close_finalized_channel(&mut accs, &tp, &signers)?;
    }

    Ok(())
}

/// Transfers the newly settled pool to explicit recipients and the payee's
/// implicit remainder share. Flooring residual remains in the escrow ATA until
/// `FINALIZED`, when it is swept to treasury just before close.
///
/// All recipient and fixed token accounts have already been validated, so this
/// helper is only responsible for payout math and signed token CPIs.
fn transfer_pool(
    accs: &mut DistributeAccounts<'_>,
    entries: &[DistributionEntry],
    payee_bps: u32,
    pool: u64,
    decimals: u8,
    token_program: &Address,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    if pool == 0 {
        return Ok(());
    }

    let mut sum_paid: u64 = 0;
    for (entry, recipient_token_account) in entries.iter().zip(accs.recipient_token_accounts.iter())
    {
        let amount = floor_bps_share(pool, entry.bps() as u32)?;
        transfer_checked_signed(
            accs.channel_token_account,
            accs.mint,
            recipient_token_account,
            accs.channel,
            amount,
            decimals,
            token_program,
            signers,
        )?;
        sum_paid = sum_paid
            .checked_add(amount)
            .expect("invariant: Σ floor(pool · bpsᵢ / 10_000) ≤ pool ≤ u64::MAX");
    }

    let payee_share = if payee_bps != 0 {
        let share = floor_bps_share(pool, payee_bps)?;
        transfer_checked_signed(
            accs.channel_token_account,
            accs.mint,
            accs.payee_token_account,
            accs.channel,
            share,
            decimals,
            token_program,
            signers,
        )?;
        share
    } else {
        0
    };

    let transferred = sum_paid
        .checked_add(payee_share)
        .expect("invariant: Σ shares ≤ pool ≤ u64::MAX");
    debug_assert!(
        transferred <= pool,
        "invariant: Σ floor shares can never exceed pool when Σ bps ≤ 10_000",
    );
    Ok(())
}

/// Sweeps all tokens left in the finalized escrow to treasury after recipient
/// payouts and any payer refund have completed.
fn sweep_finalized_residual(
    accs: &mut DistributeAccounts<'_>,
    decimals: u8,
    token_program: &Address,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    let residual = token_account_amount(
        accs.channel_token_account,
        token_program,
        PaymentChannelsError::InvalidChannelTokenAccount,
    )?;
    transfer_checked_signed(
        accs.channel_token_account,
        accs.mint,
        accs.treasury_token_account,
        accs.channel,
        residual,
        decimals,
        token_program,
        signers,
    )
}

/// Closes the finalized channel's escrow token account and tombstones the
/// channel PDA, sending both rent balances to the payer SOL account.
fn close_finalized_channel(
    accs: &mut DistributeAccounts<'_>,
    token_program: &Address,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    // Close the escrow SPL account; rent flows to payer SOL account.
    CloseAccount {
        account: accs.channel_token_account,
        destination: accs.payer,
        authority: accs.channel,
        token_program,
    }
    .invoke_signed(signers)?;

    // Tombstone the Channel PDA: move rent lamports to payer, then close.
    let rent = accs.channel.lamports();
    let new_payer_bal = accs
        .payer
        .lamports()
        .checked_add(rent)
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    accs.payer.set_lamports(new_payer_bal);
    accs.channel.set_lamports(0);
    accs.channel.close()
}
