#[cfg(feature = "idl")]
use alloc::vec::Vec;
#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::{
    AccountView, Address, ProgramResult, Resize,
    cpi::Signer,
    error::ProgramError,
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_token_2022::instructions::CloseAccount;

use crate::helpers::accounts::view::{
    ChannelContext, ChannelTokenAccountView, MintAccountView, PayeeTokenAccountView, PayerContext,
    PayerTokenAccountView, TokenContext, TokenProgramAccountView, TreasuryTokenAccountView,
};
use crate::helpers::accounts::view::{PayerAccountView, RecipientTokenAccountsView};
use crate::instructions::helpers::{DistributionEntry, DistributionPreimage, channel_signer_seeds};
use crate::state::channel::{Channel, ChannelStatus, SettlementWatermarks};
use crate::state::closed_channel::ClosedChannel;
use crate::{
    errors::PaymentChannelsError,
    helpers::accounts::view::{ChannelAccountView, Checked},
};

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
    /// Implicit-remainder destination: receives the cumulative floor delta for
    /// `10_000 - sum(bps)`. Always supplied because the accounts schema is
    /// fixed; the transfer call is skipped at the call site when the delta is
    /// zero.
    pub payee_token_account: PayeeTokenAccountView<'a>,
    /// Treasury destination: receives the final irreducible residual when the
    /// channel is finalized and ready to close.
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

/// Permissionless crank: verifies the committed preimage and pays cumulative
/// floor deltas across recipients + payee's implicit remainder share:
/// `floor(settled * bps / 10_000) - floor(payout_watermark * bps / 10_000)`.
/// In `OPEN`, residual dust stays in escrow and is automatically carried into
/// later cumulative deltas; `payout_watermark` advances to `settled` as an
/// accounted watermark. From `FINALIZED`, any final irreducible floor residual
/// is swept to treasury before close. On `FINALIZED`, also refunds the payer the unspent
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
    let accs = DistributeAccounts::try_from(accounts)?;

    // Owner / discriminator / version checks.
    let ch = Channel::from_account(&accs.channel)?;

    // Status gate.
    let status = match ChannelStatus::try_from(ch.status)? {
        ChannelStatus::Open => ChannelStatus::Open,
        ChannelStatus::Finalized => ChannelStatus::Finalized,
        ChannelStatus::Closing => return Err(PaymentChannelsError::ChannelNotDistributable.into()),
    };

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
    let mut payer_ctx =
        PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)?;

    let ch = Channel::from_account_mut(&mut channel_ctx.channel)?;

    let salt = ch.salt();

    // Validate the fixed token accounts first.
    let payee_token_account = accs
        .payee_token_account
        .check(&ch.payee, &channel_ctx.token_ctx)?;
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

    let recipient_token_accounts = accs
        .recipient_token_accounts
        .check(args.recipients.entries, &channel_ctx.token_ctx)?;

    let payee_bps = args.recipients.payee_bps();

    // SettlementWatermarks owns the invariant between the authorized settled
    // watermark and the already-accounted payout watermark.
    let settlement = ch.settlement();
    if status == ChannelStatus::Open && settlement.is_fully_accounted()? {
        return Err(PaymentChannelsError::NothingToDistribute.into());
    }
    let settled = settlement.settled();

    // Copy PDA seed bytes before dropping `ch`; signer seeds borrow these
    // arrays and must stay alive for every CPI below.
    let payer_bytes: [u8; 32] = *ch.payer.as_array();
    let payee_bytes: [u8; 32] = *ch.payee.as_array();
    let mint_bytes: [u8; 32] = *ch.mint.as_array();
    let signer_bytes: [u8; 32] = *ch.authorized_signer.as_array();
    let salt_bytes: [u8; 8] = salt.to_le_bytes();
    let bump_byte: [u8; 1] = [ch.bump];

    // Snapshot accounting fields needed after token CPIs. FINALIZED relies on
    // this payer-withdrawal gate without writing back before tombstoning.
    let deposit = ch.deposit();
    let payer_withdrawn_at = ch.payer_withdrawn_at();

    // Release the data borrow before token CPIs and the later state update.
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
        args.recipients.entries,
        payee_bps,
        settlement,
        &signers,
    )?;

    match status {
        ChannelStatus::Open => {
            let mut ch = Channel::from_account_mut(&mut channel_ctx.channel)?;
            ch.settlement_mut().account_settled();
        }
        ChannelStatus::Finalized => {
            // Payer refund branch — one-shot, gated by snapshotted payer_withdrawn_at.
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
        // Unreachable: status gate already passed
        ChannelStatus::Closing => return Err(PaymentChannelsError::ChannelNotDistributable.into()),
    }

    Ok(())
}

/// Transfers cumulative floor deltas to explicit recipients and the payee's
/// implicit remainder share. Residual dust stays in escrow between `OPEN`
/// distributions and is released automatically when a later cumulative
/// entitlement crosses the next whole token. In FINALIZED, any remaining final
/// dust is swept to treasury by the close path.
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
    settlement: SettlementWatermarks,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    if settlement.is_fully_accounted()? {
        return Ok(());
    }

    for (entry, recipient_token_account) in entries.iter().zip(recipients.iter_as_any()) {
        let amount = settlement.delta_for_bps(entry.bps() as u32)?;
        if amount > 0 {
            channel_ctx.transfer_checked_signed(&recipient_token_account, amount, signers)?;
        }
    }

    if payee_bps != 0 {
        let payee_floor = settlement.delta_for_bps(payee_bps)?;
        if payee_floor > 0 {
            channel_ctx.transfer_checked_signed(
                &payee_token_account.as_any(),
                payee_floor,
                signers,
            )?;
        }
    }

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
        .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
    let new_payer_bal = payer_ctx
        .payer
        .lamports()
        .checked_add(delta)
        .ok_or(PaymentChannelsError::DistributePayerBalanceOverflow)?;
    channel_ctx.channel.set_lamports(new_min);
    payer_ctx.payer.set_lamports(new_payer_bal);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

    use super::*;

    fn assert_cumulative_deltas_match_single_final_distribution(bps: &[u32], checkpoints: &[u64]) {
        let mut previous = 0;
        let mut total_paid = 0u64;
        let mut paid_by_share = vec![0u64; bps.len()];

        for &current in checkpoints {
            assert!(current >= previous, "checkpoints must be monotonic");
            let settlement = SettlementWatermarks::new(current, previous);

            for (index, &share_bps) in bps.iter().enumerate() {
                let delta = settlement.delta_for_bps(share_bps).unwrap();
                paid_by_share[index] = paid_by_share[index]
                    .checked_add(delta)
                    .expect("cumulative share payout must fit in u64");
                total_paid = total_paid
                    .checked_add(delta)
                    .expect("total cumulative payout must fit in u64");
            }

            assert!(
                total_paid <= current,
                "cumulative payout must never exceed settled"
            );
            previous = current;
        }

        let final_settled = checkpoints.last().copied().unwrap_or(0);
        let final_settlement = SettlementWatermarks::new(final_settled, 0);
        let mut single_final_total = 0u64;
        for (index, &share_bps) in bps.iter().enumerate() {
            let single_final_share = final_settlement.delta_for_bps(share_bps).unwrap();
            assert_eq!(paid_by_share[index], single_final_share);
            single_final_total = single_final_total
                .checked_add(single_final_share)
                .expect("single final payout must fit in u64");
        }
        assert_eq!(total_paid, single_final_total);
    }

    #[test]
    fn cumulative_deltas_telescope_for_repeated_micro_checkpoints() {
        let checkpoints: Vec<u64> = (1..=10_000).collect();

        assert_cumulative_deltas_match_single_final_distribution(&[5000, 5000], &checkpoints);
        assert_cumulative_deltas_match_single_final_distribution(&[3333, 3333, 3334], &checkpoints);
        assert_cumulative_deltas_match_single_final_distribution(&[1, 9999], &checkpoints);

        let mut thirty_two_dust_shares = Vec::with_capacity(33);
        thirty_two_dust_shares.resize(32, 1);
        thirty_two_dust_shares.push(9968);
        assert_cumulative_deltas_match_single_final_distribution(
            &thirty_two_dust_shares,
            &checkpoints,
        );

        assert_cumulative_deltas_match_single_final_distribution(&[10000], &checkpoints);
    }

    #[test]
    fn one_bps_share_crosses_whole_token_boundary_at_ten_thousand() {
        assert_eq!(
            SettlementWatermarks::new(9_999, 0)
                .delta_for_bps(1)
                .unwrap(),
            0
        );
        assert_eq!(
            SettlementWatermarks::new(10_000, 9_999)
                .delta_for_bps(1)
                .unwrap(),
            1
        );
        assert_eq!(
            SettlementWatermarks::new(9_999, 0)
                .delta_for_bps(9_999)
                .unwrap(),
            9_998
        );
        assert_eq!(
            SettlementWatermarks::new(10_000, 9_999)
                .delta_for_bps(9_999)
                .unwrap(),
            1
        );
    }

    #[test]
    fn cumulative_deltas_handle_large_u64_settled_values() {
        assert_cumulative_deltas_match_single_final_distribution(
            &[3333, 3333, 3334],
            &[u64::MAX - 10_000, u64::MAX],
        );
        assert_cumulative_deltas_match_single_final_distribution(
            &[1, 9999],
            &[u64::MAX - 10_000, u64::MAX],
        );
    }

    #[test]
    fn settlement_watermarks_report_accounting_state() {
        let fully_accounted = SettlementWatermarks::new(10, 10);
        assert_eq!(fully_accounted.unaccounted().unwrap(), 0);
        assert!(fully_accounted.is_fully_accounted().unwrap());

        let partly_accounted = SettlementWatermarks::new(10, 9);
        assert_eq!(partly_accounted.unaccounted().unwrap(), 1);
        assert!(!partly_accounted.is_fully_accounted().unwrap());
    }

    #[test]
    fn settlement_watermarks_reject_payout_watermark_above_settled() {
        let invalid = SettlementWatermarks::new(9, 10);
        assert_eq!(
            invalid.unaccounted(),
            Err(ProgramError::from(
                PaymentChannelsError::DistributePoolOverflow
            ))
        );
        assert_eq!(
            invalid.delta_for_bps(5_000),
            Err(ProgramError::from(
                PaymentChannelsError::DistributePoolOverflow
            ))
        );
    }
}
