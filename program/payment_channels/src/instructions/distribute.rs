#[cfg(feature = "idl")]
use alloc::vec::Vec;
use core::mem::MaybeUninit;

#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::{
    AccountView, Address, ProgramResult, Resize,
    cpi::{CpiAccount, Signer},
    error::ProgramError,
    instruction::InstructionAccount,
    sysvars::{Sysvar, clock::Clock, rent::Rent},
};
use pinocchio_token::instructions::{
    Batch as SplBatch, IntoBatch, TransferChecked as SplTransferChecked,
};
use pinocchio_token_2022::instructions::CloseAccount;

use crate::helpers::accounts::view::{
    ChannelContext, ChannelTokenAccountView, MintAccountView, PayeeTokenAccountView, PayerContext,
    PayerTokenAccountView, TokenContext, TokenProgramAccountView, TreasuryTokenAccountView,
};
use crate::helpers::accounts::view::{PayerAccountView, RecipientTokenAccountsView};
use crate::instructions::helpers::{
    DistributionEntry, DistributionPreimage, channel_signer_seeds, floor_bps_share,
};
use crate::state::channel::{Channel, ChannelStatus};
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
    args: &DistributeArgs<'_>,
) -> ProgramResult {
    let accs = DistributeAccounts::try_from(accounts)?;

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
    let mut payer_ctx =
        PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)?;

    let mut ch = Channel::from_account_mut(&mut channel_ctx.channel)?;

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
    let finalized = status == ChannelStatus::Finalized;
    let payer_refund_amount = if finalized && payer_withdrawn_at == 0 && deposit > settled {
        deposit - settled
    } else {
        0
    };

    if pool > 0 {
        ch.set_paid_out(settled);
    }
    if finalized && payer_withdrawn_at == 0 {
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

    let is_spl_token = channel_ctx.token_ctx.token_program.address() == &pinocchio_token::ID;
    let payee_bps = args.recipients.payee_bps();
    let use_batched_spl_path = is_spl_token
        && (finalized || (args.recipients.entries.len() + usize::from(payee_bps != 0) >= 2));

    if use_batched_spl_path {
        // Batched SPL path: recipient/payee/refund/sweep transfers are folded
        // into chunked `pinocchio_token::Batch` invocations.
        batched_distribute(
            &recipient_token_accounts,
            &channel_ctx,
            &payee_token_account,
            &payer_ctx.payer_token_account,
            &treasury_token_account,
            args.recipients.entries,
            &signers,
            payee_bps,
            pool,
            payer_refund_amount,
            finalized,
        )?;

        if finalized {
            tombstone_finalized_channel(&mut channel_ctx, &mut payer_ctx, &signers)?;
        }
    } else {
        transfer_pool(
            &recipient_token_accounts,
            &channel_ctx,
            &payee_token_account,
            args.recipients.entries,
            payee_bps,
            pool,
            &signers,
        )?;

        if finalized {
            if payer_refund_amount != 0 {
                channel_ctx.transfer_checked_signed(
                    &payer_ctx.payer_token_account.as_any(),
                    payer_refund_amount,
                    &signers,
                )?;
            }
            sweep_finalized_residual(&channel_ctx, &treasury_token_account, &signers)?;
            tombstone_finalized_channel(&mut channel_ctx, &mut payer_ctx, &signers)?;
        }
    }

    Ok(())
}

/// Transfers the newly settled pool to explicit recipients and the payee's
/// implicit remainder share via individual `TransferChecked` CPIs (per-call
/// path). Flooring residual remains in the escrow ATA until `FINALIZED`,
/// when it is swept to treasury just before close.
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

    for (entry, recipient_token_account) in entries.iter().zip(recipients.iter_as_any()) {
        let amount = floor_bps_share(pool, entry.bps() as u32)?;
        channel_ctx.transfer_checked_signed(&recipient_token_account, amount, signers)?;
    }

    if payee_bps != 0 {
        let share = floor_bps_share(pool, payee_bps)?;
        channel_ctx.transfer_checked_signed(&payee_token_account.as_any(), share, signers)?;
    }

    Ok(())
}

// Sized for the 4 KB SBF stack frame: per chunk we allocate
// `[MaybeUninit<u8>; BATCH_DATA_LEN]` (≈100 B for 8 transfers),
// `[MaybeUninit<InstructionAccount>; BATCH_ACCOUNTS_LEN]` (≈512 B),
// and `[MaybeUninit<CpiAccount>; BATCH_ACCOUNTS_LEN]` (≈1.8 KB) —
// well under the 4 KB cap. Raising this to 16 does not fit
// (~4.8 KB of buffers alone).
const BATCH_SLOTS_PER_CHUNK: usize = 8;

/// SPL batched payout path. Folds every channel-authorized SPL transfer into
/// chunked `pinocchio_token::Batch` invocations of up to
/// `BATCH_SLOTS_PER_CHUNK` logical slots each. The on-chain CPI sequence is
/// `[recipient_0, …, recipient_{N-1}, payee?, payer_refund?, sweep?]` —
/// encoded by [`BatchPhase`]; reordering those variants is a protocol-breaking
/// change. A logical slot may append one sub-instruction or skip a zero-amount
/// transfer; payee/refund phases with no payable amount advance without
/// consuming a slot.
#[allow(clippy::too_many_arguments)]
fn batched_distribute<'a>(
    recipients: &'a RecipientTokenAccountsView<'a, Checked>,
    channel_ctx: &'a ChannelContext<'a>,
    payee_token_account: &'a PayeeTokenAccountView<'a, Checked>,
    payer_token_account: &'a PayerTokenAccountView<'a, Checked>,
    treasury_token_account: &'a TreasuryTokenAccountView<'a, Checked>,
    entries: &[DistributionEntry],
    signers: &[Signer<'_, '_>],
    payee_bps: u32,
    pool: u64,
    payer_refund_amount: u64,
    finalized: bool,
) -> ProgramResult {
    // Worst-case ix-data buffer length for one chunk: all
    // `TransferChecked` sub-instructions (header + per-ix payload).
    const BATCH_DATA_LEN: usize = SplBatch::header_data_len(BATCH_SLOTS_PER_CHUNK)
        + BATCH_SLOTS_PER_CHUNK * SplTransferChecked::DATA_LEN;

    // Worst-case account buffer length for one chunk: 4 account slots
    // per `TransferChecked` (no multisig signers for channel-authorized
    // transfers).
    const BATCH_ACCOUNTS_LEN: usize = BATCH_SLOTS_PER_CHUNK * 4;

    // `InstructionAccount` and `CpiAccount` aren't `Copy`, so the
    // `[expr; N]` array-repeat syntax needs `const` fillers.
    const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();
    const UNINIT_INSTRUCTION_ACCOUNT: MaybeUninit<InstructionAccount<'_>> =
        MaybeUninit::<InstructionAccount>::uninit();
    const UNINIT_CPI_ACCOUNT: MaybeUninit<CpiAccount<'_>> = MaybeUninit::<CpiAccount>::uninit();

    let plan = BatchPlan::new(
        recipients,
        channel_ctx,
        payee_token_account,
        payer_token_account,
        treasury_token_account,
        entries,
        payee_bps,
        pool,
        payer_refund_amount,
        finalized,
    )?;
    let mut cursor = BatchCursor::default();

    while !cursor.is_done() {
        let mut data_buf = [UNINIT_BYTE; BATCH_DATA_LEN];
        let mut ia_buf = [UNINIT_INSTRUCTION_ACCOUNT; BATCH_ACCOUNTS_LEN];
        let mut acc_buf = [UNINIT_CPI_ACCOUNT; BATCH_ACCOUNTS_LEN];
        let mut batch = SplBatch::new(&mut data_buf, &mut ia_buf, &mut acc_buf)?;
        let pushed_any = cursor.fill_chunk(&plan, &mut batch)?;

        if pushed_any {
            batch.invoke_signed(signers)?;
        }
    }

    Ok(())
}

/// Immutable inputs for SPL batched distribution run.
///
/// `BatchCursor` owns mutable progress through this plan; `BatchPlan` keeps
/// the account references, payout parameters, and FINALIZED snapshot stable
/// across every chunk.
struct BatchPlan<'accounts, 'entries> {
    /// Recipient token accounts, aligned 1:1 with `entries`.
    recipients: &'accounts RecipientTokenAccountsView<'accounts, Checked>,
    /// Channel PDA, escrow token account, mint, and token-program context.
    channel_ctx: &'accounts ChannelContext<'accounts>,
    /// Payee destination token account for the implicit remainder share.
    payee_token_account: &'accounts PayeeTokenAccountView<'accounts, Checked>,
    /// Payer destination token account for the one-shot FINALIZED refund.
    payer_token_account: &'accounts PayerTokenAccountView<'accounts, Checked>,
    /// Treasury destination token account for the FINALIZED floor-residual sweep.
    treasury_token_account: &'accounts TreasuryTokenAccountView<'accounts, Checked>,
    /// Recipient distribution entries, aligned 1:1 with `recipients`.
    entries: &'entries [DistributionEntry],
    /// Newly settled pool to distribute (`settled - paid_out`).
    pool: u64,
    /// Payee basis points used to lazily compute the implicit remainder share.
    payee_bps: u32,
    /// One-shot payer refund amount for the first FINALIZED run.
    payer_refund_amount: u64,
    /// Escrow balance snapshotted before any CPI; used to derive the sweep.
    escrow_at_entry: u64,
    /// FINALIZED gate for the sweep phase.
    finalized: bool,
}

impl<'accounts, 'entries> BatchPlan<'accounts, 'entries> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        recipients: &'accounts RecipientTokenAccountsView<'accounts, Checked>,
        channel_ctx: &'accounts ChannelContext<'accounts>,
        payee_token_account: &'accounts PayeeTokenAccountView<'accounts, Checked>,
        payer_token_account: &'accounts PayerTokenAccountView<'accounts, Checked>,
        treasury_token_account: &'accounts TreasuryTokenAccountView<'accounts, Checked>,
        entries: &'entries [DistributionEntry],
        payee_bps: u32,
        pool: u64,
        payer_refund_amount: u64,
        finalized: bool,
    ) -> Result<Self, ProgramError> {
        // FINALIZED-only snapshot. Combined with the cursor's running
        // outflow, yields the treasury sweep as
        // `escrow_at_entry - cumulative_outflow`.
        let escrow_at_entry = if finalized {
            channel_ctx
                .token_ctx
                .token_program
                .amount(&channel_ctx.channel_token_account.as_any())?
        } else {
            0
        };

        Ok(Self {
            recipients,
            channel_ctx,
            payee_token_account,
            payer_token_account,
            treasury_token_account,
            entries,
            pool,
            payee_bps,
            payer_refund_amount,
            escrow_at_entry,
            finalized,
        })
    }
}

/// Batched CPI phase order. This is the protocol order for the SPL batched
/// path and must remain aligned with the per-call FINALIZED tail.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum BatchPhase {
    /// Explicit recipient payouts, in distribution-entry order.
    #[default]
    Recipients,
    /// Payee's implicit remainder share, emitted only when it floors non-zero.
    Payee,
    /// One-shot payer refund of unsettled deposit headroom; omitted at zero.
    PayerRefund,
    /// Finalized floor-residual sweep; consumes a slot even at zero amount.
    Sweep,
    /// Terminal state; no more logical batch slots remain.
    Done,
}

#[derive(Default)]
struct BatchCursor {
    /// Current phase in the fixed batched CPI sequence.
    phase: BatchPhase,
    /// Index of the next recipient entry to process during `Recipients`.
    next_recipient: usize,
    /// Running sum of every payout amount processed so far across all chunks.
    /// Sweep derives its amount from this; zero-amount logical slots do not
    /// change the value.
    cumulative_outflow: u64,
}

impl BatchCursor {
    #[inline]
    fn is_done(&self) -> bool {
        self.phase == BatchPhase::Done
    }

    /// Fills one batch with up to `BATCH_SLOTS_PER_CHUNK` logical slots.
    /// Reached recipient/sweep slots with amount zero emit no sub-instruction;
    /// payee/refund phases with no payable amount are skipped before consuming
    /// a slot.
    fn fill_chunk<'accounts, 'entries>(
        &mut self,
        plan: &BatchPlan<'accounts, 'entries>,
        batch: &mut SplBatch<'accounts, '_>,
    ) -> Result<bool, ProgramError> {
        let mut pushed_any = false;

        for _ in 0..BATCH_SLOTS_PER_CHUNK {
            let Some(item) = self.next_slot(plan)? else {
                break;
            };
            pushed_any |= item.push(plan, batch)?;
        }

        Ok(pushed_any)
    }

    fn next_slot<'accounts, 'entries>(
        &mut self,
        plan: &BatchPlan<'accounts, 'entries>,
    ) -> Result<Option<BatchItem<'accounts>>, ProgramError> {
        while !self.is_done() {
            match self.phase {
                BatchPhase::Recipients => {
                    if self.next_recipient == plan.entries.len() {
                        self.phase = BatchPhase::Payee;
                        continue;
                    }

                    let amount =
                        floor_bps_share(plan.pool, plan.entries[self.next_recipient].bps() as u32)?;
                    self.add_outflow(amount)?;
                    let item = BatchItem::Transfer {
                        to: &plan.recipients[self.next_recipient],
                        amount,
                    };
                    self.next_recipient += 1;
                    return Ok(Some(item));
                }
                BatchPhase::Payee => {
                    self.phase = BatchPhase::PayerRefund;
                    if plan.payee_bps == 0 {
                        continue;
                    }

                    let amount = floor_bps_share(plan.pool, plan.payee_bps)?;
                    if amount == 0 {
                        continue;
                    }

                    self.add_outflow(amount)?;
                    return Ok(Some(BatchItem::Transfer {
                        to: plan.payee_token_account,
                        amount,
                    }));
                }
                BatchPhase::PayerRefund => {
                    self.phase = BatchPhase::Sweep;
                    if plan.payer_refund_amount == 0 {
                        continue;
                    }

                    self.add_outflow(plan.payer_refund_amount)?;
                    return Ok(Some(BatchItem::Transfer {
                        to: plan.payer_token_account,
                        amount: plan.payer_refund_amount,
                    }));
                }
                BatchPhase::Sweep => {
                    self.phase = BatchPhase::Done;
                    if !plan.finalized {
                        continue;
                    }

                    let amount = plan
                        .escrow_at_entry
                        .checked_sub(self.cumulative_outflow)
                        .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
                    return Ok(Some(BatchItem::Transfer {
                        to: plan.treasury_token_account,
                        amount,
                    }));
                }
                BatchPhase::Done => break,
            }
        }
        Ok(None)
    }

    #[inline]
    fn add_outflow(&mut self, amount: u64) -> ProgramResult {
        self.cumulative_outflow = self
            .cumulative_outflow
            .checked_add(amount)
            .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
        Ok(())
    }
}

/// One logical slot in a batched SPL payout chunk.
enum BatchItem<'accounts> {
    /// Channel-authorized token transfer; zero amount emits no sub-instruction.
    Transfer {
        /// Destination token account for this payout.
        to: &'accounts AccountView,
        /// Amount to transfer from the channel escrow.
        amount: u64,
    },
}

impl<'accounts> BatchItem<'accounts> {
    /// Appends this item to `batch`, returning whether a sub-instruction was
    /// emitted. Zero-amount transfers are logical slots but not SPL CPIs.
    #[inline]
    fn push<'entries>(
        self,
        plan: &BatchPlan<'accounts, 'entries>,
        batch: &mut SplBatch<'accounts, '_>,
    ) -> Result<bool, ProgramError> {
        match self {
            Self::Transfer { to, amount } => {
                if amount == 0 {
                    return Ok(false);
                }

                SplTransferChecked::new(
                    &plan.channel_ctx.channel_token_account,
                    &plan.channel_ctx.token_ctx.mint,
                    to,
                    &plan.channel_ctx.channel,
                    amount,
                    plan.channel_ctx.token_ctx.decimals,
                )
                .into_batch(batch)?;
                Ok(true)
            }
        }
    }
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
