//! Mechanical CPI provenance checks. Successful validation is **not** an
//! issuer approval, a credit authorization, or a durable replay check.
use pinocchio::{AccountView, Address, error::ProgramError};

use crate::{
    HookContext, HookDescriptor,
    channel::{ChannelAccountView, ChannelStatus},
    hooks::{
        MAX_HOOK_ACCOUNTS, MAX_STATIC_CONTEXT, Operation, Phase, descriptor_commitment,
        hook_authority,
    },
};

/// All expectations must come from independently trusted recipient policy or
/// recipient-owned state, never from the callback payload or its channel owner.
pub struct CallbackExpectations<'a> {
    pub channel_program: &'a Address,
    pub callback_program: &'a Address,
    pub channel: &'a Address,
    pub token_program: &'a Address,
    pub descriptors: &'a [HookDescriptor; 4],
}

/// Mechanically validated context and the current accounting snapshot.
/// Providers still enforce customer/issuer binding, cap, nonce, expiry,
/// distribution policy, token custody/delegation and their replay records.
pub struct ValidatedCallback {
    pub context: HookContext,
    pub status: ChannelStatus,
    pub salt: u64,
    pub deposit: u64,
}

fn require(value: bool) -> Result<(), ProgramError> {
    if value {
        Ok(())
    } else {
        Err(ProgramError::InvalidAccountData)
    }
}

/// Accounts must be exactly `[scoped_authority, readonly_channel, extras...]`.
/// The callback envelope, phase/operation/executed tags, channel owner/layout/
/// PDA, live guard/sequence, immutable configuration and account privileges are
/// checked together before a context is returned.
///
/// ```
/// use payment_channel_interface::validation::{
///     CallbackExpectations, ValidatedCallback, validate_callback,
/// };
/// use pinocchio::{AccountView, error::ProgramError};
///
/// fn inspect_callback(
///     accounts: &[AccountView],
///     payload: &[u8],
///     trusted: &CallbackExpectations<'_>,
/// ) -> Result<ValidatedCallback, ProgramError> {
///     validate_callback(accounts, payload, trusted)
/// }
/// ```
pub fn validate_callback(
    accounts: &[AccountView],
    data: &[u8],
    expected: &CallbackExpectations<'_>,
) -> Result<ValidatedCallback, ProgramError> {
    let phase = Phase::try_from(*data.get(9).ok_or(ProgramError::InvalidInstructionData)?)?;
    let descriptor = &expected.descriptors[phase as usize];
    require(descriptor.enabled() && descriptor.program == *expected.callback_program)?;
    let n = descriptor.account_count as usize;
    let static_len = descriptor.static_len as usize;
    require(n <= MAX_HOOK_ACCOUNTS && static_len <= MAX_STATIC_CONTEXT)?;
    let c = HookContext::decode_callback(
        data,
        &descriptor.entrypoint,
        &descriptor.static_context[..static_len],
    )?;
    let operation = Operation::try_from(c.operation)?;
    let funding = matches!(operation, Operation::Open | Operation::TopUp);
    require(funding == matches!(phase, Phase::PreFund | Phase::PostFund))?;
    let post = matches!(phase, Phase::PostFund | Phase::PostDistribute);
    require(c.executed == u8::from(post))?;
    if accounts.len() != n + 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let channel = &accounts[1];
    let channel_view = ChannelAccountView::new(channel, expected.channel_program)?;
    require(channel.address() == expected.channel && c.channel == *expected.channel.as_array())?;
    require(
        authority.is_signer()
            && !authority.is_writable()
            && !channel.is_signer()
            && !channel.is_writable(),
    )?;
    channel_view.with_v2(|ch| {
        let (pda, bump) = ch.find_pda(expected.channel_program);
        require(pda == *channel.address() && bump == ch.bump())?;
        let hooks = ch.hooks()?;
        let commitment = descriptor_commitment(expected.descriptors);
        require(
            hooks.commitment == commitment
                && c.configuration == commitment
                && hooks.descriptors == *expected.descriptors
                && hooks.in_progress == 1
                && c.sequence != 0
                && c.sequence == u64::from_le_bytes(hooks.sequence),
        )?;
        let (scoped, _) = hook_authority(
            expected.channel_program,
            channel.address(),
            &commitment,
            phase,
            expected.callback_program,
        );
        require(*authority.address() == scoped)?;
        for (i, (meta, account)) in descriptor.accounts[..n]
            .iter()
            .zip(&accounts[2..])
            .enumerate()
        {
            require(
                meta.writable <= 1
                    && meta.address == *account.address()
                    && meta.address != scoped
                    && meta.address != *channel.address()
                    && meta.address != *expected.callback_program
                    && !descriptor.accounts[..i]
                        .iter()
                        .any(|other| other.address == meta.address)
                    && !account.is_signer()
                    && account.is_writable() == (meta.writable == 1),
            )?;
        }
        require(
            c.open_slot == ch.open_slot()
                && c.payer == *ch.payer().as_array()
                && c.payee == *ch.payee().as_array()
                && c.mint == *ch.mint().as_array()
                && c.authorized_signer == *ch.authorized_signer().as_array()
                && c.distribution_hash == ch.distribution_hash()
                && c.token_program == *expected.token_program.as_array(),
        )?;
        if post {
            require(
                c.deposit_after == ch.deposit()
                    && c.payout_after == ch.payout_watermark()
                    && c.withdrawn_after == ch.payer_withdrawn_at(),
            )?;
        } else {
            require(
                c.deposit_before == ch.deposit()
                    && c.settled_before == ch.settled()
                    && c.payout_before == ch.payout_watermark()
                    && c.withdrawn_before == ch.payer_withdrawn_at(),
            )?;
        }
        Ok(ValidatedCallback {
            context: c,
            status: ch.status()?,
            salt: ch.salt(),
            deposit: ch.deposit(),
        })
    })
}
