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

use crate::errors::PaymentChannelsError;
use crate::helpers::accounts::view::{
    ChannelAccountView, ChannelContext, ChannelTokenAccountView, MintAccountView,
    PayeeTokenAccountView, PayerAccountView, PayerTokenAccountView, PayoutBeneficiary,
    RecipientTokenAccountsView, TokenContext, TokenProgramAccountView, TreasuryTokenAccountView,
};
#[cfg(feature = "idl")]
use crate::instructions::helpers::DistributionEntry;
use crate::instructions::helpers::{DistributionPreimage, Transfer, channel_signer_seeds};
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

/// Fixed 10-slot head + dynamic recipient tail. Recipient ATAs sit in
/// `recipient_token_accounts` in the same order as the active entries in
/// `DistributeArgs::recipients`; clients append them as remaining accounts.
pub struct DistributeAccounts<'a> {
    /// Channel PDA whose accounting state is advanced and, on FINALIZED,
    /// tombstoned in place at [`AccountDiscriminator::ClosedChannel`] after
    /// all token movement is complete. The address stays alive forever and
    /// is never recycled, blocking voucher replay against a re-initialized
    /// channel at the same seeds.
    pub channel: ChannelAccountView<'a>,
    /// Original payer wallet. Receives the **token** refund (`deposit − settled`)
    /// on FINALIZED cleanup and must match [`Channel::payer`](crate::Channel::payer).
    pub payer: PayerAccountView<'a>,
    /// Receives the **SOL rent** (escrow-ATA close + freed PDA delta) on
    /// FINALIZED cleanup; must match
    /// [`Channel::rent_payer`](crate::Channel::rent_payer). Not a signer —
    /// receiving lamports needs no signature, so `distribute` stays
    /// permissionless. MAY equal [`Self::payer`].
    pub rent_payer: &'a mut AccountView,
    /// Escrow; source for all splits, the payee implicit remainder, and the
    /// FINALIZED payer refund.
    pub channel_token_account: ChannelTokenAccountView<'a>,
    /// Payer refund destination. Used **only** by the FINALIZED branch when
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0` and
    /// `deposit > settled`.
    pub payer_token_account: PayerTokenAccountView<'a>,
    /// Implicit-remainder destination: receives the cumulative floor delta for
    /// `10_000 − Σ bps`. Always supplied because the accounts schema is fixed;
    /// a zero-delta payout still validates the canonical ATA and then no-ops
    /// in `Transfer`.
    pub payee_token_account: PayeeTokenAccountView<'a>,
    /// Treasury destination: receives the final irreducible residual when the
    /// channel is finalized and ready to close.
    pub treasury_token_account: TreasuryTokenAccountView<'a>,
    /// Mint bound into the channel and used for every token transfer.
    pub mint: MintAccountView<'a>,
    /// SPL Token or Token-2022 program used by the escrow and payout ATAs.
    pub token_program: TokenProgramAccountView<'a>,
    /// Signer PDA for the self-CPI that emits
    /// [`crate::events::PayoutRedirected`] when a poisoned beneficiary share is
    /// forfeited to treasury.
    pub event_authority: &'a AccountView,
    /// This program's ID; CPI target for the redirect-event emission.
    pub self_program: &'a AccountView,
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
            rent_payer,
            channel_token_account,
            payer_token_account,
            payee_token_account,
            treasury_token_account,
            mint,
            token_program,
            event_authority,
            self_program,
            recipient_rest @ ..,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            channel: channel.into(),
            payer: payer.into(),
            rent_payer,
            channel_token_account: channel_token_account.into(),
            payer_token_account: payer_token_account.into(),
            payee_token_account: payee_token_account.into(),
            treasury_token_account: treasury_token_account.into(),
            mint: mint.into(),
            token_program: token_program.into(),
            event_authority,
            self_program,
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
///
/// Operator note: in `OPEN`, if a recipient's or the payee's canonical ATA is
/// unusable (missing/uninitialized, frozen, closed/malformed, carrying an
/// unsupported Token-2022 extension, or with a reassigned authority), that
/// nonzero share is redirected to the treasury and `payout_watermark` still
/// advances — the beneficiary permanently forfeits it (a [`PayoutRedirected`]
/// event is emitted for off-chain observability). The same redirect applies to
/// the payer's refund ATA on `FINALIZED`: when a refund is due
/// ([`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0` and
/// `deposit > settled`) and that ATA is unusable, the unspent headroom is
/// forfeited to the treasury — and because finalization tombstones the channel
/// in the same instruction, there is no later crank to reclaim it. Ensure the
/// recipient, payee, and payer ATAs exist and are healthy (or withdraw the
/// payer headroom beforehand) before cranking `distribute`.
///
/// [`PayoutRedirected`]: crate::events::PayoutRedirected
pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &DistributeArgs<'_>,
) -> ProgramResult {
    let accs = DistributeAccounts::try_from(accounts)?;

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
    // Bind the rent recipient to the funder recorded at `open`, so a caller
    // cannot redirect the freed rent to an arbitrary account on cleanup.
    if accs.rent_payer.address() != &ch.rent_payer {
        return Err(PaymentChannelsError::InvalidChannelRentPayer.into());
    }

    // drop initial ch
    drop(ch);

    let token_ctx = TokenContext::new(accs.mint, accs.token_program)?;
    let mut channel_ctx = ChannelContext::new(accs.channel, accs.channel_token_account, token_ctx)?;

    let ch = Channel::from_account_mut(&mut channel_ctx.channel)?;

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

    // SettlementWatermarks owns the invariant between the authorized settled
    // watermark and the already-accounted payout watermark. Recipient, payee,
    // and payer ATAs are validated lazily at each payout so a poisoned
    // beneficiary cannot brick the whole crank.
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
    let is_finalized = status.is_finalized();

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

    // Collect payouts first; CPIs run in one shot at `flush` below.
    let mut transfer = Transfer::new(&channel_ctx, &signers);
    // Copied out so the redirect-event emission can reference it without
    // re-borrowing `channel_ctx` (held by `transfer`) below.
    let channel_address = *channel_ctx.channel.address();

    for (entry, recipient_account) in args
        .recipients
        .entries
        .iter()
        .zip(accs.recipient_token_accounts.iter())
    {
        let amount = settlement.delta_for_bps(entry.bps() as u32)?;
        let destination = channel_ctx.token_ctx.payout_destination(
            PayoutBeneficiary::Recipient,
            recipient_account,
            &entry.recipient,
            amount,
            &treasury_token_account,
            program_id,
            accs.event_authority,
            accs.self_program,
            &channel_address,
        )?;
        transfer.push(destination, amount)?;
    }

    let payee_share = settlement.delta_for_bps(args.recipients.payee_bps())?;
    let payee_destination = channel_ctx.token_ctx.payout_destination(
        PayoutBeneficiary::Payee,
        &accs.payee_token_account,
        &Address::new_from_array(payee_bytes),
        payee_share,
        &treasury_token_account,
        program_id,
        accs.event_authority,
        accs.self_program,
        &channel_address,
    )?;
    transfer.push(payee_destination, payee_share)?;

    if is_finalized {
        // Payer refund branch is one-shot and lazily validated. A payer who
        // poisons their canonical ATA cannot block OPEN or no-refund FINALIZED
        // distributions; if a refund is due, the unsupported-account payout is
        // redirected to treasury and the channel can still close.
        if payer_withdrawn_at == 0 && deposit > settled {
            let payer_refund = deposit - settled;
            let payer_destination = channel_ctx.token_ctx.payout_destination(
                PayoutBeneficiary::Payer,
                &accs.payer_token_account,
                &Address::new_from_array(payer_bytes),
                payer_refund,
                &treasury_token_account,
                program_id,
                accs.event_authority,
                accs.self_program,
                &channel_address,
            )?;
            transfer.push(payer_destination, payer_refund)?;
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
        tombstone_finalized_channel(&mut channel_ctx, accs.rent_payer, &signers)?;
    } else {
        // OPEN: advance the accounted watermark to the settled watermark so
        // future cumulative deltas only cover newly settled amounts.
        let mut ch = Channel::from_account_mut(&mut channel_ctx.channel)?;
        ch.settlement_mut().mark_as_settled();
    }

    Ok(())
}

/// Closes the finalized channel's escrow token account and tombstones the
/// Channel PDA in place: shrinks the data buffer to
/// [`ClosedChannel::LEN`], writes the [`AccountDiscriminator::ClosedChannel`]
/// payload, and refunds the freed rent delta to the rent payer. The PDA stays
/// alive forever — program-owned, non-empty — so the system program rejects
/// any future `CreateAccount` against the same seeds, blocking voucher
/// replay against a re-initialized channel.
fn tombstone_finalized_channel(
    channel_ctx: &mut ChannelContext<'_>,
    rent_payer: &mut AccountView,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    // Close the escrow SPL account; its rent flows to the rent payer.
    CloseAccount {
        account: &channel_ctx.channel_token_account,
        destination: rent_payer,
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
    // delta to the rent payer. The PDA must remain rent-exempt so the runtime
    // never garbage-collects it, which is what keeps the address reserved.
    let rent = Rent::get()?;
    let new_min = rent.try_minimum_balance(ClosedChannel::LEN)?;
    let current = channel_ctx.channel.lamports();
    let delta = current
        .checked_sub(new_min)
        .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
    let new_rent_payer_bal = rent_payer
        .lamports()
        .checked_add(delta)
        .ok_or(PaymentChannelsError::DistributePayerBalanceOverflow)?;
    channel_ctx.channel.set_lamports(new_min);
    rent_payer.set_lamports(new_rent_payer_bal);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::state::channel::SettlementWatermarks;

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
