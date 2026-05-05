#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult, Resize,
    cpi::Signer,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock, rent::Rent},
};
use pinocchio_token_2022::instructions::CloseAccount;

use crate::helpers::accounts::view::{
    ChannelContext, ChannelTokenAccountView, MintAccountView, PayeeTokenAccountView, PayerContext,
    PayerTokenAccountView, TokenContext, TokenProgramAccountView, TreasuryTokenAccountView,
};
use crate::helpers::accounts::view::{PayerAccountView, RecipientTokenAccountsView};
use crate::instructions::helpers::{
    DistributionEntry, DistributionRecipients, channel_signer_seeds, floor_bps_share,
};
use crate::state::channel::{Channel, ChannelStatus};
use crate::state::closed_channel::ClosedChannel;
use crate::state::{Transmutable, load};
use crate::{
    errors::PaymentChannelsError,
    helpers::accounts::view::{ChannelAccountView, Checked},
};

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
    /// tombstoned in place at [`AccountDiscriminator::ClosedChannel`] after
    /// all token movement is complete. The address stays alive forever and
    /// is never recycled, blocking voucher replay against a re-initialized
    /// channel at the same seeds.
    pub channel: ChannelAccountView<'a>,
    /// Original payer wallet. Receives SOL rent on FINALIZED cleanup and must
    /// match [`Channel::payer`](crate::Channel::payer).
    pub payer: PayerAccountView<'a>,
    /// Escrow; source for all splits, the payee implicit remainder, and the
    /// FINALIZED payer refund.
    pub channel_token_account: ChannelTokenAccountView<'a>,
    /// Payer refund destination. Used **only** by the FINALIZED branch when
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0` and
    /// `deposit > settled`.
    pub payer_token_account: PayerTokenAccountView<'a>,
    /// Implicit-remainder destination: receives
    /// `floor(pool * (10_000 − Σ bps) / 10_000)` whenever `payee_bps > 0`.
    /// Always supplied because the accounts schema is fixed; the transfer
    /// call is skipped at the call site when `Σ bps == 10_000`.
    pub payee_token_account: PayeeTokenAccountView<'a>,
    /// Treasury destination: receives flooring residual when the channel is
    /// finalized and ready to close.
    pub treasury_token_account: TreasuryTokenAccountView<'a>,
    /// Mint bound into the channel and used for every token transfer.
    pub mint: MintAccountView<'a>,
    /// SPL Token or Token-2022 program used by the escrow and payout ATAs.
    pub token_program: TokenProgramAccountView<'a>,
    /// Dynamic recipient ATA tail, ordered exactly like the active entries in
    /// the revealed distribution plan.
    pub recipient_token_accounts: RecipientTokenAccountsView<'a>,
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
            channel: channel.into(),
            payer: payer.into(),
            channel_token_account: channel_token_account.into(),
            payer_token_account: payer_token_account.into(),
            payee_token_account: payee_token_account.into(),
            treasury_token_account: treasury_token_account.into(),
            mint: mint.into(),
            token_program: token_program.into(),
            recipient_token_accounts: recipient_rest.into(),
        })
    }
}

/// Permissionless crank: verifies the committed preimage and pays
/// [`settled`](Channel::settled) `−` [`paid_out`](Channel::paid_out) across
/// recipients + payee's implicit remainder share. From `OPEN`, flooring
/// residual stays in escrow. From `FINALIZED`, residual is swept to treasury.
/// On `FINALIZED`, also refunds the payer the unspent
/// [`deposit`](Channel::deposit) `−` [`settled`](Channel::settled) headroom
/// (if not already withdrawn), closes the escrow ATA, and tombstones the
/// Channel PDA in place via discriminator realloc to
/// [`ClosedChannel`](crate::ClosedChannel) — refunding the rent delta to the
/// payer while keeping the address program-owned forever.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &DistributeArgs,
) -> ProgramResult {
    let accs = DistributeAccounts::try_from(accounts)?;

    // Load and validate the channel identity before inspecting token accounts.
    // The channel address is captured first because `ch` borrows its data.
    let now = Clock::get()?.unix_timestamp;

    // Owner / discriminator / version checks.
    let channel = accs.channel.check()?;
    let ch = Channel::from_account(&channel)?;

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

    // drop initial ch
    drop(ch);

    let token_ctx = TokenContext::new(accs.mint, accs.token_program)?;
    let mut channel_ctx = ChannelContext::new(channel, accs.channel_token_account, token_ctx)
        .map_err(|_| PaymentChannelsError::InvalidChannelTokenAccount)?;
    let mut payer_ctx =
        PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)?;

    let mut ch = Channel::from_account_mut(&mut channel_ctx.channel)?;

    let salt = ch.salt();

    // Validate the fixed token accounts first.
    let payee_token_account = accs
        .payee_token_account
        .check(&ch.payee, &channel_ctx.token_ctx)
        .map_err(|_| PaymentChannelsError::InvalidPayeeTokenAccount)?;
    let treasury_token_account = accs
        .treasury_token_account
        .check(&channel_ctx.token_ctx)
        .map_err(|_| PaymentChannelsError::TreasuryAddressMismatch)?;

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

    let recipient_token_accounts = accs
        .recipient_token_accounts
        .check(distribution.entries, &channel_ctx.token_ctx)?;

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
        &recipient_token_accounts,
        &channel_ctx,
        &payee_token_account,
        distribution.entries,
        distribution.payee_bps,
        pool,
        &signers,
    )?;

    if status == ChannelStatus::Finalized {
        // Payer refund branch — one-shot, gated by payer_withdrawn_at.
        if payer_withdrawn_at == 0 && deposit > settled {
            channel_ctx.transfer_checked_signed(
                &payer_ctx.payer_token_account.as_any(),
                deposit - settled,
                &signers,
            )?;
        }
        sweep_finalized_residual(&channel_ctx, &treasury_token_account, &signers)?;
        tombstone_finalized_channel(&mut channel_ctx, &mut payer_ctx, &signers)?;
    }

    Ok(())
}

/// Transfers the newly settled pool to explicit recipients and the payee's
/// implicit remainder share. Flooring residual remains in the escrow ATA until
/// `FINALIZED`, when it is swept to treasury just before close.
///
/// All recipient and fixed token accounts have already been validated, so this
/// helper is only responsible for payout math and signed token CPIs.
#[allow(clippy::too_many_arguments)]
fn transfer_pool(
    recipients: &RecipientTokenAccountsView<'_, Checked>,
    channel_ctx: &ChannelContext,
    payee_token_account: &PayeeTokenAccountView<'_, Checked>,
    entries: &[DistributionEntry],
    payee_bps: u32,
    pool: u64,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    if pool == 0 {
        return Ok(());
    }

    let mut sum_paid: u64 = 0;
    for (entry, recipient_token_account) in entries.iter().zip(recipients.iter_as_any()) {
        let amount = floor_bps_share(pool, entry.bps() as u32)?;
        channel_ctx.transfer_checked_signed(&recipient_token_account, amount, signers)?;
        sum_paid = sum_paid
            .checked_add(amount)
            .expect("invariant: Σ floor(pool · bpsᵢ / 10_000) ≤ pool ≤ u64::MAX");
    }

    let payee_share = if payee_bps != 0 {
        let share = floor_bps_share(pool, payee_bps)?;

        channel_ctx.transfer_checked_signed(&payee_token_account.as_any(), share, signers)?;

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
    channel_ctx: &ChannelContext<'_>,
    treasury_token_account: &TreasuryTokenAccountView<'_, Checked>,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    let residual = channel_ctx
        .token_ctx
        .token_program
        .amount(&channel_ctx.channel_token_account.as_any())?;
    channel_ctx.transfer_checked_signed(&treasury_token_account.as_any(), residual, signers)
}

/// Closes the finalized channel's escrow token account and tombstones the
/// Channel PDA in place: shrinks the data buffer to
/// [`ClosedChannel::LEN`], writes the [`AccountDiscriminator::ClosedChannel`]
/// payload, and refunds the freed rent delta to the payer. The PDA stays
/// alive forever — program-owned, non-empty — so the system program rejects
/// any future `CreateAccount` against the same seeds, blocking voucher
/// replay against a re-initialized channel.
fn tombstone_finalized_channel(
    channel_ctx: &mut ChannelContext<'_>,
    payer_ctx: &mut PayerContext,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    // Close the escrow SPL account; rent flows to payer SOL account.
    CloseAccount {
        account: &channel_ctx.channel_token_account,
        destination: &payer_ctx.payer,
        authority: &channel_ctx.channel,
        token_program: channel_ctx.token_ctx.token_program.address(),
    }
    .invoke_signed(signers)?;

    // Shrink the Channel PDA data from `Channel::LEN` (216) to
    // `ClosedChannel::LEN` (1).
    channel_ctx.channel.resize(ClosedChannel::LEN)?;

    // Overwrite the now-truncated buffer with the tombstone header.
    {
        let mut data = channel_ctx.channel.try_borrow_mut()?;
        ClosedChannel::write_into(&mut data)?;
    }

    // Rebalance lamports to the new rent-exempt minimum and refund the
    // delta to the payer. The PDA must remain rent-exempt so the runtime
    // never garbage-collects it, which is what keeps the address reserved.
    let rent = Rent::get()?;
    let new_min = rent.try_minimum_balance(ClosedChannel::LEN)?;
    let current = channel_ctx.channel.lamports();
    let delta = current
        .checked_sub(new_min)
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    let new_payer_bal = payer_ctx
        .payer
        .lamports()
        .checked_add(delta)
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    channel_ctx.channel.set_lamports(new_min);
    payer_ctx.payer.set_lamports(new_payer_bal);
    Ok(())
}
