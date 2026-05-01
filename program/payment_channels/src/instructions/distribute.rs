use crate::constants::TREASURY_OWNER;
use crate::errors::PaymentChannelsError;
use crate::helpers::{AccountValidator, TokenProgramKind, ValidatedMint, ValidatedTokenAccount};
use crate::instructions::helpers::{
    DistributionEntry, DistributionRecipients, channel_signer_seeds, floor_bps_share,
};
use crate::state::channel::{Channel, ChannelStatus};
use crate::state::{Transmutable, load};
#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::Signer,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
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
    let accs = DistributeAccounts::try_from(accounts)?;

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
    let program = TokenProgramKind::try_from_address(accs.token_program.address())?;
    let mint = accs.mint.validate_as_mint(program)?;

    let salt = ch.salt();

    // Validate the fixed token accounts; recipient ATAs are validated
    // inline in `transfer_pool`.
    let channel_ta = accs
        .channel_token_account
        .validate_as_token_account(&channel_address, &mint)
        .map_err(|_| PaymentChannelsError::InvalidChannelTokenAccount)?;
    let payer_ta = accs
        .payer_token_account
        .validate_as_token_account(&ch.payer, &mint)
        .map_err(|_| PaymentChannelsError::InvalidPayerTokenAccount)?;
    let payee_ta = accs
        .payee_token_account
        .validate_as_token_account(&ch.payee, &mint)
        .map_err(|_| PaymentChannelsError::InvalidPayeeTokenAccount)?;
    let treasury_ta = accs
        .treasury_token_account
        .validate_as_token_account(&TREASURY_OWNER, &mint)
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
        &channel_ta,
        &payee_ta,
        accs.recipient_token_accounts,
        distribution.entries,
        distribution.payee_bps,
        pool,
        accs.channel,
        &mint,
        &signers,
    )?;

    if status == ChannelStatus::Finalized {
        // Payer refund branch — one-shot, gated by payer_withdrawn_at.
        if payer_withdrawn_at == 0 && deposit > settled {
            channel_ta.transfer_signed_to(&payer_ta, accs.channel, deposit - settled, &signers)?;
        }
        sweep_finalized_residual(&channel_ta, &treasury_ta, accs.channel, &signers)?;
        close_finalized_channel(&channel_ta, accs.payer, accs.channel, &signers)?;
    }

    Ok(())
}

/// Transfers the newly settled pool to explicit recipients and the payee's
/// implicit remainder share. Flooring residual remains in the escrow ATA until
/// `FINALIZED`, when it is swept to treasury just before close. Recipient
/// ATAs are validated inline; tx atomicity reverts prior transfers on failure.
#[allow(clippy::too_many_arguments)]
fn transfer_pool<'mint>(
    channel_ta: &ValidatedTokenAccount<'mint, '_>,
    payee_ta: &ValidatedTokenAccount<'mint, '_>,
    recipient_views: &[AccountView],
    entries: &[DistributionEntry],
    payee_bps: u32,
    pool: u64,
    authority: &AccountView,
    mint: &'mint ValidatedMint<'_>,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    if pool == 0 {
        return Ok(());
    }

    let mut sum_paid: u64 = 0;
    for (entry, recipient_view) in entries.iter().zip(recipient_views.iter()) {
        let amount = floor_bps_share(pool, entry.bps() as u32)?;
        let recipient_ta = recipient_view
            .validate_as_token_account(&entry.recipient, mint)
            .map_err(|e| match e {
                PaymentChannelsError::AddressMismatch => {
                    PaymentChannelsError::InvalidRecipientAccount
                }
                other => other,
            })?;
        channel_ta.transfer_signed_to(&recipient_ta, authority, amount, signers)?;
        sum_paid = sum_paid
            .checked_add(amount)
            .expect("invariant: Σ floor(pool · bpsᵢ / 10_000) ≤ pool ≤ u64::MAX");
    }

    let payee_share = if payee_bps != 0 {
        let share = floor_bps_share(pool, payee_bps)?;
        channel_ta.transfer_signed_to(payee_ta, authority, share, signers)?;
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
fn sweep_finalized_residual<'mint>(
    channel_ta: &ValidatedTokenAccount<'mint, '_>,
    treasury_ta: &ValidatedTokenAccount<'mint, '_>,
    authority: &AccountView,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    let residual = channel_ta
        .amount()
        .map_err(|_| PaymentChannelsError::InvalidChannelTokenAccount)?;
    channel_ta.transfer_signed_to(treasury_ta, authority, residual, signers)
}

/// Closes the finalized channel's escrow token account and tombstones the
/// channel PDA, sending both rent balances to the payer SOL account.
fn close_finalized_channel<'mint>(
    channel_ta: &ValidatedTokenAccount<'mint, '_>,
    payer: &mut AccountView,
    channel: &mut AccountView,
    signers: &[Signer<'_, '_>],
) -> ProgramResult {
    // Close the escrow SPL account; rent flows to payer SOL account.
    channel_ta.close_signed_to(payer, channel, signers)?;

    // Tombstone the Channel PDA: move rent lamports to payer, then close.
    let rent = channel.lamports();
    let new_payer_bal = payer
        .lamports()
        .checked_add(rent)
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    payer.set_lamports(new_payer_bal);
    channel.set_lamports(0);
    channel.close()
}
