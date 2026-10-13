use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::Signer,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::errors::PaymentChannelsError;
use crate::helpers::accounts::view::{
    ChannelAccountView, ChannelContext, ChannelTokenAccountView, MintAccountView, PayerAccountView,
    PayerContext, PayerTokenAccountView, TokenContext, TokenProgramAccountView,
};
use crate::hooks::HookContextRuntime;
use crate::instructions::helpers::channel_signer_seeds;
use crate::state::channel::{Channel, ChannelStatus};

/// Instruction discriminator byte for `withdrawPayer`.
pub const DISCRIMINATOR: u8 = 8;
pub const WITH_HOOKS_DISCRIMINATOR: u8 = 13;

pub struct WithdrawPayerAccounts<'a> {
    /// Must equal [`Channel::payer`](crate::Channel::payer) and be a signer.
    pub payer: PayerAccountView<'a>,
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at)
    /// stamped; the PDA is not closed.
    pub channel: ChannelAccountView<'a>,
    pub channel_token_account: ChannelTokenAccountView<'a>,
    pub payer_token_account: PayerTokenAccountView<'a>,
    pub mint: MintAccountView<'a>,
    pub token_program: TokenProgramAccountView<'a>,
}

impl<'a> TryFrom<&'a mut [AccountView]> for WithdrawPayerAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [
            payer,
            channel,
            channel_token_account,
            payer_token_account,
            mint,
            token_program,
        ] = accounts
        else {
            return Err(PaymentChannelsError::NotEnoughAccountKeys.into());
        };
        Ok(Self {
            payer: payer.into(),
            channel: channel.into(),
            channel_token_account: channel_token_account.into(),
            payer_token_account: payer_token_account.into(),
            mint: mint.into(),
            token_program: token_program.into(),
        })
    }
}

/// Payer-only refund of [`deposit`](crate::Channel::deposit) `−`
/// [`settled`](crate::Channel::settled) during `SEALED`; records
/// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `= now` and
/// does **not** close the PDA.
pub fn process(_program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    process_inner(accounts, false)
}

pub fn process_with_hooks(_program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    process_inner(accounts, true)
}

fn process_inner(accounts: &mut [AccountView], with_hooks: bool) -> ProgramResult {
    let split = if with_hooks { 6 } else { accounts.len() };
    let (accounts, hook_accounts) = accounts
        .split_at_mut_checked(split)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let accs = WithdrawPayerAccounts::try_from(accounts)?;
    let now = Clock::get()?.unix_timestamp;
    // Zero is the "not withdrawn" sentinel, including on local validators.
    let now = if with_hooks { now.max(1) } else { now };

    // Signer check before any account reads.
    if !accs.payer.is_signer() {
        return Err(PaymentChannelsError::MissingRequiredSignature.into());
    }

    // Owner / discriminator / version checks.
    let ch = Channel::from_account(&accs.channel)?;
    ch.require_hooks(with_hooks)?;

    // Status gate: SEALED only.
    if ch.status != ChannelStatus::Sealed as u8 {
        return Err(PaymentChannelsError::InvalidChannelStatus.into());
    }

    // Identity + one-shot guard (all channel-state checks before token validation).
    if accs.payer.address() != &ch.payer {
        return Err(PaymentChannelsError::InvalidChannelPayer.into());
    }
    if ch.payer_withdrawn_at() != 0 {
        return Err(PaymentChannelsError::PayerAlreadyWithdrawn.into());
    }
    if accs.mint.address() != &ch.mint {
        return Err(PaymentChannelsError::InvalidChannelMint.into());
    }

    // Snapshot accounting + PDA seed material before dropping ch.
    let deposit = ch.deposit();
    let settled = ch.settled();
    let payer_bytes: [u8; 32] = *ch.payer.as_array();
    let payee_bytes: [u8; 32] = *ch.payee.as_array();
    let mint_bytes: [u8; 32] = *ch.mint.as_array();
    let signer_bytes: [u8; 32] = *ch.authorized_signer.as_array();
    let salt_bytes: [u8; 8] = ch.salt().to_le_bytes();
    let open_slot_bytes: [u8; 8] = ch.open_slot().to_le_bytes();
    let bump_byte: [u8; 1] = [ch.bump];
    drop(ch);

    // Validate token contexts + ATA derivations.
    let token_ctx = TokenContext::new(accs.mint, accs.token_program)?;
    let mut channel_ctx = ChannelContext::new(accs.channel, accs.channel_token_account, token_ctx)?;
    let payer_ctx =
        PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)?;

    let signer_seeds = channel_signer_seeds(
        &payer_bytes,
        &payee_bytes,
        &mint_bytes,
        &signer_bytes,
        &salt_bytes,
        &open_slot_bytes,
        &bump_byte,
    );
    let signers = [Signer::from(&signer_seeds)];

    let refund = deposit
        .checked_sub(settled)
        .ok_or(PaymentChannelsError::RefundCalculationOverflow)?;
    let hook_state = if with_hooks {
        crate::hooks::validate_tail(&channel_ctx.channel, hook_accounts, 2)?;
        let context = crate::hooks::HookContext::begin(
            &mut channel_ctx.channel,
            channel_ctx.token_ctx.token_program.address(),
            DISCRIMINATOR,
            0,
            0,
            refund,
        )?;
        let before = channel_ctx
            .token_ctx
            .token_program
            .amount(&channel_ctx.channel_token_account.as_any())?;
        crate::hooks::invoke(&channel_ctx.channel, hook_accounts, &context, 2)?;
        crate::hooks::revalidate(&channel_ctx, Some(&payer_ctx.payer_token_account), before)?;
        Some((context, before))
    } else {
        None
    };
    channel_ctx.transfer_checked_signed(
        &payer_ctx.payer_token_account.as_any(),
        refund,
        &signers,
    )?;
    Channel::from_account_mut(&mut channel_ctx.channel)?.set_payer_withdrawn_at(now);

    if let Some((mut hook_context, escrow_before)) = hook_state {
        hook_context.refund_transferred_to_payer = refund;
        hook_context.actual(&channel_ctx.channel)?;
        crate::hooks::invoke(&channel_ctx.channel, hook_accounts, &hook_context, 3)?;
        crate::hooks::revalidate(
            &channel_ctx,
            Some(&payer_ctx.payer_token_account),
            escrow_before
                .checked_sub(refund)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        )?;
        crate::hooks::finish(&mut channel_ctx.channel)?;
    }

    Ok(())
}
