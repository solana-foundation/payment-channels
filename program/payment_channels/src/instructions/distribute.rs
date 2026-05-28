#[cfg(feature = "idl")]
use alloc::vec::Vec;

#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::{
    AccountView, Address, ProgramResult, Resize,
    cpi::Signer,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock, rent::Rent},
};
use pinocchio_token_2022::instructions::CloseAccount;

use crate::errors::PaymentChannelsError;
use crate::helpers::accounts::view::{
    ChannelAccountView, ChannelContext, ChannelTokenAccountView, MintAccountView,
    PayeeTokenAccountView, PayerAccountView, PayerTokenAccountView, PayoutBeneficiary,
    RecipientTokenAccountsView, TokenContext, TokenProgramAccountView, TreasuryTokenAccountView,
};
#[cfg(feature = "idl")]
use crate::instructions::helpers::DistributionEntry;
use crate::instructions::helpers::{
    DistributionPreimage, Transfer, channel_signer_seeds, floor_bps_share,
};
use crate::state::channel::{Channel, ChannelStatus};
use crate::state::closed_channel::ClosedChannel;

/// Instruction discriminator byte for `distribute`.
pub const DISCRIMINATOR: u8 = 7;

#[derive(Debug, Clone, Copy)]
pub struct DistributeArgs<'a> {
    /// Reveal of the plan committed at `open`. Rehashed on-chain; digest must
    /// equal [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    pub recipients: DistributionPreimage<'a>,
}

#[cfg(feature = "idl")]
#[allow(dead_code)]
#[derive(CodamaType)]
#[codama(name = "distribute_args")]
pub struct DistributeArgsWire {
    pub recipients: Vec<DistributionEntry>,
}

impl<'a> DistributeArgs<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        Ok(Self {
            recipients: DistributionPreimage::load(data)?,
        })
    }
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
    /// Implicit-remainder destination for
    /// `floor(pool * (10_000 − Σ bps) / 10_000)`. Always supplied because the
    /// accounts schema is fixed; zero-share payouts still validate the
    /// canonical ATA and then no-op in `Transfer`.
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
    args: &DistributeArgs<'_>,
) -> ProgramResult {
    let mut accs = DistributeAccounts::try_from(accounts)?;

    // Load and validate the channel identity before inspecting token accounts.
    // The channel address is captured first because `ch` borrows its data.
    let now = Clock::get()?.unix_timestamp;

    // Owner / discriminator / version checks.
    let ch = Channel::from_account(&accs.channel)?;

    // Status gate.
    let status = ChannelStatus::try_from(ch.status)?;
    if !matches!(status, ChannelStatus::Open | ChannelStatus::Finalized) {
        return Err(PaymentChannelsError::ChannelNotDistributable.into());
    }

    // Identity.
    if accs.payer.address() != &ch.payer {
        return Err(PaymentChannelsError::InvalidChannelPayer.into());
    }
    if accs.mint.address() != &ch.mint {
        return Err(PaymentChannelsError::InvalidChannelMint.into());
    }

    // drop initial ch
    drop(ch);

    let token_ctx = TokenContext::new(accs.mint, accs.token_program)?;
    let mut channel_ctx = ChannelContext::new(accs.channel, accs.channel_token_account, token_ctx)?;

    let mut ch = Channel::from_account_mut(&mut channel_ctx.channel)?;

    let salt = ch.salt();

    // Treasury is needed in both OPEN (skip-and-redirect destination) and
    // FINALIZED (residual sweep + skip-and-redirect). Validate it eagerly;
    // the payee, recipient, and payer ATAs are validated lazily so a
    // poisoned beneficiary cannot brick the whole crank.
    let treasury_token_account = accs.treasury_token_account.check(&channel_ctx.token_ctx)?;

    let digest = args.recipients.preimage_hash();
    if digest != ch.distribution_hash {
        return Err(PaymentChannelsError::InvalidDistributionHash.into());
    }

    // Hash equality proves the revealed distribution matches the plan
    // committed by `open`.
    if accs.recipient_token_accounts.len() != args.recipients.entries.len() {
        return Err(PaymentChannelsError::RecipientAccountCountMismatch.into());
    }

    // Pool = settled − paid_out.
    let pool = ch
        .settled()
        .checked_sub(ch.paid_out())
        .ok_or(PaymentChannelsError::DistributePoolOverflow)?;
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
    let is_finalized = status.is_finalized();

    ch.set_paid_out(settled);
    if is_finalized && payer_withdrawn_at == 0 {
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

    // Collect payouts first; CPIs run in one shot at `flush` below.
    let mut transfer = Transfer::new(&channel_ctx, &signers);

    for (entry, recipient_account) in args
        .recipients
        .entries
        .iter()
        .zip(accs.recipient_token_accounts.iter())
    {
        let amount = floor_bps_share(pool, entry.bps() as u32)?;
        transfer.push(
            channel_ctx.token_ctx.payout_destination(
                PayoutBeneficiary::Recipient,
                recipient_account,
                &entry.recipient,
                amount,
                &treasury_token_account,
            )?,
            amount,
        )?;
    }

    let payee_share = floor_bps_share(pool, args.recipients.payee_bps())?;
    transfer.push(
        channel_ctx.token_ctx.payout_destination(
            PayoutBeneficiary::Payee,
            &accs.payee_token_account,
            &Address::new_from_array(payee_bytes),
            payee_share,
            &treasury_token_account,
        )?,
        payee_share,
    )?;

    if is_finalized {
        // Payer refund branch is one-shot and lazily validated. A payer who
        // poisons their canonical ATA cannot block OPEN or no-refund FINALIZED
        // distributions; if a refund is due, the unsupported-account payout is
        // redirected to treasury and the channel can still close.
        if payer_withdrawn_at == 0 && deposit > settled {
            let payer_refund = deposit - settled;
            transfer.push(
                channel_ctx.token_ctx.payout_destination(
                    PayoutBeneficiary::Payer,
                    &accs.payer_token_account,
                    &Address::new_from_array(payer_bytes),
                    payer_refund,
                    &treasury_token_account,
                )?,
                payer_refund,
            )?;
        }

        let escrow_at_entry = channel_ctx
            .token_ctx
            .token_program
            .amount(&channel_ctx.channel_token_account.as_any())?;

        // Invariant: escrow_at_entry == scheduled_outflow() + treasury_sweep.
        // Treasury captures bps flooring dust not assigned to recipients/payee.
        let treasury_sweep = escrow_at_entry
            .checked_sub(transfer.scheduled_outflow())
            .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
        transfer.push(&treasury_token_account, treasury_sweep)?;
    }

    // Execute every queued transfer (direct CPI or batched SPL `Batch`).
    transfer.flush()?;

    if is_finalized {
        // Close escrow ATA and tombstone the channel PDA in place.
        tombstone_finalized_channel(&mut channel_ctx, &mut accs.payer, &signers)?;
    }

    Ok(())
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
    payer: &mut PayerAccountView<'_>,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    // Close the escrow SPL account; rent flows to payer SOL account.
    CloseAccount {
        account: &channel_ctx.channel_token_account,
        destination: payer,
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
        .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
    let new_payer_bal = payer
        .lamports()
        .checked_add(delta)
        .ok_or(PaymentChannelsError::DistributePayerBalanceOverflow)?;
    channel_ctx.channel.set_lamports(new_min);
    payer.set_lamports(new_payer_bal);
    Ok(())
}
