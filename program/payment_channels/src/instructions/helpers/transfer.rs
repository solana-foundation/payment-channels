use core::mem::{MaybeUninit, size_of};

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

/// Channel-authorized token mover. Callers `push(to, amount)` payouts in
/// protocol order and call `flush()` once; the helper hides batching,
/// chunking, and the per-token-program CPI shape (e.g. SPL Token or Token-2022).
///
/// On `flush()`: nothing queued is a no-op; otherwise, when the channel's
/// token program advertises batching via [`supports_transfer_batching`] and
/// the queue holds two or more transfers, payouts go out as chunked `Batch`
/// CPIs. Every other case falls back to one `TransferChecked` CPI per payout.
///
/// Zero-amount calls are silently dropped and emit no CPI.
///
/// [`supports_transfer_batching`]: crate::instructions::helpers::accounts::view::TokenProgramKind::supports_transfer_batching
pub struct Transfer<'a> {
    channel_ctx: &'a ChannelContext<'a>,
    signers: &'a [Signer<'a, 'a>],
    scheduled_outflow: u64,
    pending: [MaybeUninit<PendingTransfer<'a>>; MAX_PENDING],
    pending_len: usize,
}

/// One escrow payout waiting for [`Transfer::flush`].
struct PendingTransfer<'a> {
    to: &'a AccountView,
    amount: u64,
}

/// SPL `Batch` slot count per CPI invocation.
///
/// Per chunk we allocate, on the SBF stack, `[MaybeUninit<u8>; BATCH_DATA_LEN]`
/// (~100 B for 8 transfers), `[MaybeUninit<InstructionAccount>; BATCH_ACCOUNTS_LEN]`
/// (~512 B), and `[MaybeUninit<CpiAccount>; BATCH_ACCOUNTS_LEN]` (~1.8 KB) —
/// well under the 4 KB SBF stack-frame cap. Raising this to 16 already does
/// not fit (~4.8 KB of buffers alone). [`Transfer::flush_batched`] enforces
/// the budget at compile time with a `const _: () = assert!(... <= 4096)`.
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

    /// Reserve one queue slot and accumulate `amount` into scheduled outflow.
    fn reserve_transfer_amount(&mut self, amount: u64) -> Result<(), PaymentChannelsError> {
        if self.pending_len >= MAX_PENDING {
            return Err(PaymentChannelsError::DistributeTransferQueueOverflow);
        }
        self.scheduled_outflow = self
            .scheduled_outflow
            .checked_add(amount)
            .ok_or(PaymentChannelsError::DistributeBalanceCalculationOverflow)?;
        Ok(())
    }

    /// Schedule a channel-authorized `TransferChecked` from escrow to `to`.
    /// Zero `amount` is ignored and does not consume a queue slot.
    pub fn push(&mut self, to: &'a AccountView, amount: u64) -> Result<(), PaymentChannelsError> {
        if amount == 0 {
            return Ok(());
        }
        self.reserve_transfer_amount(amount)?;
        self.pending[self.pending_len].write(PendingTransfer { to, amount });
        self.pending_len += 1;
        Ok(())
    }

    /// Sum of every non-zero queued amount. Used by `distribute::process` to
    /// derive the SEALED treasury sweep as `escrow_at_entry - scheduled_outflow()`.
    pub fn scheduled_outflow(&self) -> u64 {
        self.scheduled_outflow
    }

    /// Emit every queued payout as token CPIs. No-op when nothing was queued.
    /// Token programs that support batching use one `Batch` CPI per chunk
    /// once the queue holds two or more transfers; otherwise each payout is
    /// a separate `TransferChecked` CPI.
    pub fn flush(self) -> ProgramResult {
        if self.pending_len == 0 {
            return Ok(());
        }
        if self.should_batch() {
            self.flush_batched()
        } else {
            self.flush_direct()
        }
    }

    /// True when chunked `Batch` CPIs save CUs over per-transfer CPIs.
    /// The token program must expose batching at all, and a lone transfer
    /// is skipped so we don't pay the batch header for no benefit.
    fn should_batch(&self) -> bool {
        self.channel_ctx.token_ctx.kind.supports_transfer_batching() && self.pending_len >= 2
    }

    /// Initialized prefix of the queued payouts.
    fn pending(&self) -> &[PendingTransfer<'a>] {
        // SAFETY: indices `0..self.pending_len` were initialized by every
        // successful `push()` call, and `pending_len` is only ever incremented
        // after a successful `write()`. `MaybeUninit<T>` has the same layout
        // as `T`, so reinterpreting the initialized prefix as `&[PendingTransfer]`
        // is sound; the returned slice cannot outlive `&self`.
        unsafe {
            core::slice::from_raw_parts(
                self.pending.as_ptr().cast::<PendingTransfer<'a>>(),
                self.pending_len,
            )
        }
    }

    /// Emit one `TransferChecked` CPI per queued payout via the channel's token program.
    fn flush_direct(self) -> ProgramResult {
        for pt in self.pending() {
            T22TransferChecked {
                from: &self.channel_ctx.channel_token_account,
                mint: &self.channel_ctx.token_ctx.mint,
                to: pt.to,
                authority: &self.channel_ctx.channel,
                amount: pt.amount,
                decimals: self.channel_ctx.token_ctx.decimals,
                token_program: self.channel_ctx.token_ctx.token_program.address(),
            }
            .invoke_signed(self.signers)?;
        }
        Ok(())
    }

    /// Emit queued payouts as SPL Token `Batch` CPIs, up to
    /// [`BATCH_SLOTS_PER_CHUNK`] transfers per invoke.
    fn flush_batched(self) -> ProgramResult {
        /// Worst-case ix-data buffer length for one chunk: the batch header
        /// plus every `TransferChecked` sub-instruction payload.
        const BATCH_DATA_LEN: usize = SplBatch::header_data_len(BATCH_SLOTS_PER_CHUNK)
            + BATCH_SLOTS_PER_CHUNK * SplTransferChecked::DATA_LEN;
        /// Worst-case account buffer length for one chunk: 4 account metas
        /// per channel-authorized `TransferChecked` (no multisig signers).
        const BATCH_ACCOUNTS_LEN: usize = BATCH_SLOTS_PER_CHUNK * 4;
        const _: () = assert!(
            size_of::<Transfer<'_>>()
                + BATCH_DATA_LEN
                + size_of::<[MaybeUninit<InstructionAccount<'_>>; BATCH_ACCOUNTS_LEN]>()
                + size_of::<[MaybeUninit<CpiAccount<'_>>; BATCH_ACCOUNTS_LEN]>()
                <= 4096
        );

        const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();
        const UNINIT_INSTRUCTION_ACCOUNT: MaybeUninit<InstructionAccount<'_>> =
            MaybeUninit::<InstructionAccount>::uninit();
        const UNINIT_CPI_ACCOUNT: MaybeUninit<CpiAccount<'_>> = MaybeUninit::<CpiAccount>::uninit();

        for chunk in self.pending().chunks(BATCH_SLOTS_PER_CHUNK) {
            let mut data_buf = [UNINIT_BYTE; BATCH_DATA_LEN];
            let mut ia_buf = [UNINIT_INSTRUCTION_ACCOUNT; BATCH_ACCOUNTS_LEN];
            let mut acc_buf = [UNINIT_CPI_ACCOUNT; BATCH_ACCOUNTS_LEN];
            let mut batch = SplBatch::new(&mut data_buf, &mut ia_buf, &mut acc_buf)?;

            for pt in chunk {
                SplTransferChecked::new(
                    &self.channel_ctx.channel_token_account,
                    &self.channel_ctx.token_ctx.mint,
                    pt.to,
                    &self.channel_ctx.channel,
                    pt.amount,
                    self.channel_ctx.token_ctx.decimals,
                )
                .into_batch(&mut batch)?;
            }

            batch.invoke_signed(self.signers)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn max_pending_matches_distribute_worst_case() {
        assert_eq!(MAX_PENDING, MAX_DISTRIBUTION_RECIPIENTS + 3);
    }

    #[test]
    fn transfer_struct_fits_stack_budget() {
        assert!(size_of::<Transfer<'_>>() <= 1024);
    }
}
