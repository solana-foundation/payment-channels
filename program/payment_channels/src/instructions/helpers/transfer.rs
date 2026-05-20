use core::mem::MaybeUninit;

use pinocchio::{
    AccountView, ProgramResult,
    cpi::{CpiAccount, Signer},
    instruction::InstructionAccount,
};
use pinocchio_token::instructions::{
    Batch as SplBatch, IntoBatch, TransferChecked as SplTransferChecked,
};
use pinocchio_token_2022::instructions::TransferChecked as T22TransferChecked;

use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::MAX_DISTRIBUTION_RECIPIENTS;
use crate::instructions::helpers::accounts::view::ChannelContext;

/// Channel-authorized token mover. Callers `queue(to, amount)` payouts in
/// protocol order and call `flush()` once; the helper hides batching,
/// chunking, and the SPL vs Token-2022 split.
///
/// On `flush()`: nothing queued is a no-op; otherwise [`should_batch`](Transfer::should_batch)
/// picks batched SPL `Batch` CPIs (≥2 transfers) vs direct `TransferChecked` CPIs
/// (Token-2022, or a lone SPL transfer).
///
/// Zero-amount calls are silently dropped (preserves existing
/// `transfer_checked_signed` short-circuit; e.g., sweep with no residual
/// emits no CPI).
pub struct Transfer<'a> {
    channel_ctx: &'a ChannelContext<'a>,
    signers: &'a [Signer<'a, 'a>],
    scheduled_outflow: u64,
    pending: [MaybeUninit<PendingTransfer<'a>>; MAX_PENDING],
    pending_len: usize,
}

/// One escrow payout waiting for [`Transfer::flush`].
#[derive(Copy, Clone)]
struct PendingTransfer<'a> {
    to: &'a AccountView,
    amount: u64,
}

// Sized for the 4 KB SBF stack frame: per chunk we allocate
// `[MaybeUninit<u8>; BATCH_DATA_LEN]` (≈100 B for 8 transfers),
// `[MaybeUninit<InstructionAccount>; BATCH_ACCOUNTS_LEN]` (≈512 B),
// and `[MaybeUninit<CpiAccount>; BATCH_ACCOUNTS_LEN]` (≈1.8 KB) —
// well under the 4 KB cap. Raising this to 16 does not fit
// (~4.8 KB of buffers alone).
const BATCH_SLOTS_PER_CHUNK: usize = 8;

/// Sized for distribute's worst case: 32 recipients + payee + payer-refund + treasury-sweep.
const MAX_PENDING: usize = MAX_DISTRIBUTION_RECIPIENTS + 3;

impl<'a> Transfer<'a> {
    /// Empty transfer collector for `channel_ctx` payouts signed with `signers`.
    pub fn new(channel_ctx: &'a ChannelContext<'a>, signers: &'a [Signer<'a, 'a>]) -> Self {
        Self {
            channel_ctx,
            signers,
            scheduled_outflow: 0,
            pending: [const { MaybeUninit::uninit() }; MAX_PENDING],
            pending_len: 0,
        }
    }

    /// Schedule a channel-authorized `TransferChecked` from escrow to `to`.
    /// Zero `amount` is ignored and does not consume a queue slot.
    pub fn queue(&mut self, to: &'a AccountView, amount: u64) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }
        self.scheduled_outflow = self
            .scheduled_outflow
            .checked_add(amount)
            .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
        if self.pending_len >= MAX_PENDING {
            return Err(PaymentChannelsError::DistributePoolOverflow.into());
        }
        self.pending[self.pending_len].write(PendingTransfer { to, amount });
        self.pending_len += 1;
        Ok(())
    }

    /// Sum of every non-zero queued amount. Used by `distribute::process` to
    /// derive the FINALIZED treasury sweep as `escrow_at_entry - scheduled_outflow()`.
    pub fn scheduled_outflow(&self) -> u64 {
        self.scheduled_outflow
    }

    /// Emit every queued payout as token CPIs. No-op when nothing was queued.
    /// Classic SPL with two or more transfers uses one `Batch` CPI per chunk;
    /// otherwise each payout is a separate `TransferChecked` CPI.
    pub fn flush(self) -> ProgramResult {
        if self.pending_len == 0 {
            return Ok(());
        }

        if self.should_batch() {
            flush_batched(self)
        } else {
            flush_direct(self)
        }
    }

    /// Whether [`flush`](Self::flush) should use `pinocchio_token::Batch` CPIs.
    fn should_batch(&self) -> bool {
        self.channel_ctx.token_ctx.kind.uses_spl_batch_cpi() && self.pending_len >= 2
    }
}

/// Emit one `TransferChecked` CPI per queued payout via the channel's token program.
fn flush_direct(transfer: Transfer<'_>) -> ProgramResult {
    for i in 0..transfer.pending_len {
        let pt = unsafe { transfer.pending[i].assume_init_read() };
        T22TransferChecked {
            from: &transfer.channel_ctx.channel_token_account,
            mint: &transfer.channel_ctx.token_ctx.mint,
            to: pt.to,
            authority: &transfer.channel_ctx.channel,
            amount: pt.amount,
            decimals: transfer.channel_ctx.token_ctx.decimals,
            token_program: transfer.channel_ctx.token_ctx.token_program.address(),
        }
        .invoke_signed(transfer.signers)?;
    }
    Ok(())
}

/// Emit queued payouts as SPL Token `Batch` CPIs, up to
/// [`BATCH_SLOTS_PER_CHUNK`] transfers per invoke.
fn flush_batched(transfer: Transfer<'_>) -> ProgramResult {
    const BATCH_DATA_LEN: usize = SplBatch::header_data_len(BATCH_SLOTS_PER_CHUNK)
        + BATCH_SLOTS_PER_CHUNK * SplTransferChecked::DATA_LEN;
    const BATCH_ACCOUNTS_LEN: usize = BATCH_SLOTS_PER_CHUNK * 4;

    const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();
    const UNINIT_INSTRUCTION_ACCOUNT: MaybeUninit<InstructionAccount<'_>> =
        MaybeUninit::<InstructionAccount>::uninit();
    const UNINIT_CPI_ACCOUNT: MaybeUninit<CpiAccount<'_>> = MaybeUninit::<CpiAccount>::uninit();

    let mut offset = 0;
    while offset < transfer.pending_len {
        let chunk_end = (offset + BATCH_SLOTS_PER_CHUNK).min(transfer.pending_len);

        let mut data_buf = [UNINIT_BYTE; BATCH_DATA_LEN];
        let mut ia_buf = [UNINIT_INSTRUCTION_ACCOUNT; BATCH_ACCOUNTS_LEN];
        let mut acc_buf = [UNINIT_CPI_ACCOUNT; BATCH_ACCOUNTS_LEN];
        let mut batch = SplBatch::new(&mut data_buf, &mut ia_buf, &mut acc_buf)?;

        for i in offset..chunk_end {
            let pt = unsafe { transfer.pending[i].assume_init_read() };
            SplTransferChecked::new(
                &transfer.channel_ctx.channel_token_account,
                &transfer.channel_ctx.token_ctx.mint,
                pt.to,
                &transfer.channel_ctx.channel,
                pt.amount,
                transfer.channel_ctx.token_ctx.decimals,
            )
            .into_batch(&mut batch)?;
        }

        batch.invoke_signed(transfer.signers)?;
        offset = chunk_end;
    }

    Ok(())
}
