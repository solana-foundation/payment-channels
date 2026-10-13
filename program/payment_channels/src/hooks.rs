//! V2 lifecycle ABI. Configuration is inline and immutable; no optional sidecar.
use borsh::BorshSerialize;
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer, invoke_signed_with_bounds},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
};

use crate::{
    Channel,
    event_engine::EventBuf,
    helpers::{
        accounts::validation::AccountValidator, accounts::view::ChannelContext, hash::sha256,
    },
};

pub const MAX_HOOK_ACCOUNTS: usize = 4;
pub const MAX_STATIC_CONTEXT: usize = 32;
pub const AUTHORITY_SEED: &[u8] = b"channel_hook";
const ZERO: Address = Address::new_from_array([0; 32]);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookMeta {
    pub address: Address,
    pub writable: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookDescriptor {
    pub program: Address,
    pub entrypoint: [u8; 8],
    pub account_count: u8,
    pub static_len: u8,
    pub static_context: [u8; MAX_STATIC_CONTEXT],
    pub accounts: [HookMeta; MAX_HOOK_ACCOUNTS],
}

impl HookDescriptor {
    pub const EMPTY: Self = Self {
        program: ZERO,
        entrypoint: [0; 8],
        account_count: 0,
        static_len: 0,
        static_context: [0; MAX_STATIC_CONTEXT],
        accounts: [HookMeta {
            address: ZERO,
            writable: 0,
        }; MAX_HOOK_ACCOUNTS],
    };

    pub fn enabled(&self) -> bool {
        self.program != ZERO
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookState {
    pub in_progress: u8,
    pub sequence: [u8; 8],
    pub commitment: [u8; 32],
    pub descriptors: [HookDescriptor; 4],
}

impl HookState {
    pub const EMPTY: Self = Self {
        in_progress: 0,
        sequence: [0; 8],
        commitment: [0; 32],
        descriptors: [HookDescriptor::EMPTY; 4],
    };

    pub fn enabled(&self) -> bool {
        self.descriptors.iter().any(HookDescriptor::enabled)
    }

    /// Sparse open encoding; unused storage is canonical zero padding.
    pub fn parse(mut bytes: &[u8]) -> Result<Self, ProgramError> {
        let mut state = Self::EMPTY;
        for descriptor in &mut state.descriptors {
            match take::<1>(&mut bytes)?[0] {
                0 => continue,
                1 => {}
                _ => return Err(ProgramError::InvalidInstructionData),
            }
            descriptor.program = Address::new_from_array(take(&mut bytes)?);
            descriptor.entrypoint = take(&mut bytes)?;
            descriptor.account_count = take::<1>(&mut bytes)?[0];
            descriptor.static_len = take::<1>(&mut bytes)?[0];
            if descriptor.program == ZERO
                || descriptor.program == crate::ID
                || descriptor.account_count as usize > MAX_HOOK_ACCOUNTS
                || descriptor.static_len as usize > MAX_STATIC_CONTEXT
            {
                return Err(ProgramError::InvalidInstructionData);
            }
            let n = descriptor.static_len as usize;
            if bytes.len() < n {
                return Err(ProgramError::InvalidInstructionData);
            }
            descriptor.static_context[..n].copy_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            for i in 0..descriptor.account_count as usize {
                let address = Address::new_from_array(take(&mut bytes)?);
                let writable = take::<1>(&mut bytes)?[0];
                if writable > 1
                    || descriptor.accounts[..i]
                        .iter()
                        .any(|m| m.address == address)
                {
                    return Err(ProgramError::InvalidInstructionData);
                }
                descriptor.accounts[i] = HookMeta { address, writable };
            }
        }
        if !bytes.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        // SAFETY: repr(C), alignment one, all fields initialized, no padding.
        let encoded =
            unsafe { core::slice::from_raw_parts(state.descriptors.as_ptr().cast::<u8>(), 824) };
        state.commitment = sha256(encoded);
        Ok(state)
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], ProgramError> {
    if bytes.len() < N {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (value, rest) = bytes.split_at(N);
    *bytes = rest;
    Ok(value.try_into().unwrap())
}

pub fn check_entry(accounts: &[AccountView]) -> ProgramResult {
    for account in accounts {
        if account.owned_by(&crate::ID) && account.data_len() == Channel::LEN {
            let ch = Channel::from_account(account)?;
            if ch.hooks.in_progress != 0 {
                return Err(ProgramError::InvalidAccountData);
            }
        }
    }
    Ok(())
}

/// Callback payload after the committed eight-byte entrypoint. Borsh/LE,
/// without enum tags or padding beyond these explicitly declared fields.
#[derive(Clone, Copy, BorshSerialize)]
pub struct HookContext {
    pub abi_version: u8,
    pub phase: u8,
    pub operation: u8,
    pub executed: u8,
    pub channel: [u8; 32],
    pub sequence: u64,
    pub open_slot: u64,
    pub payer: [u8; 32],
    pub payee: [u8; 32],
    pub mint: [u8; 32],
    pub token_program: [u8; 32],
    pub configuration: [u8; 32],
    pub authorized_signer: [u8; 32],
    pub distribution_hash: [u8; 32],
    pub deposit_before: u64,
    pub settled_before: u64,
    pub payout_before: u64,
    pub withdrawn_before: i64,
    pub funding_requested: u64,
    pub merchant_due: u64,
    pub refund_due: u64,
    pub funding_transferred: u64,
    pub merchant_transferred: u64,
    pub refund_transferred_to_payer: u64,
    pub redirected_principal: u64,
    pub treasury_surplus: u64,
    pub deposit_after: u64,
    pub payout_after: u64,
    pub withdrawn_after: i64,
    pub refund_destination: [u8; 32],
}

impl HookContext {
    pub fn begin(
        channel: &mut AccountView,
        token_program: &Address,
        operation: u8,
        funding: u64,
        merchant_due: u64,
        refund_due: u64,
    ) -> Result<Self, ProgramError> {
        let address = *channel.address().as_array();
        let mut ch = Channel::from_account_mut(channel)?;
        if ch.hooks.in_progress != 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        let sequence = u64::from_le_bytes(ch.hooks.sequence)
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        ch.hooks.sequence = sequence.to_le_bytes();
        ch.hooks.in_progress = 1;
        // Even a zero-refund operation reports the canonical destination,
        // rather than trusting an otherwise-unused caller-supplied account.
        let (refund_destination, _) = Address::find_program_address(
            &[ch.payer.as_ref(), token_program.as_ref(), ch.mint.as_ref()],
            &pinocchio_associated_token_account::ID,
        );
        Ok(Self {
            abi_version: 1,
            phase: 0,
            operation,
            executed: 0,
            channel: address,
            sequence,
            open_slot: ch.open_slot(),
            payer: *ch.payer.as_array(),
            payee: *ch.payee.as_array(),
            mint: *ch.mint.as_array(),
            token_program: *token_program.as_array(),
            configuration: ch.hooks.commitment,
            authorized_signer: *ch.authorized_signer.as_array(),
            distribution_hash: ch.distribution_hash,
            deposit_before: ch.deposit(),
            settled_before: ch.settled(),
            payout_before: ch.payout_watermark(),
            withdrawn_before: ch.payer_withdrawn_at(),
            funding_requested: funding,
            merchant_due,
            refund_due,
            funding_transferred: 0,
            merchant_transferred: 0,
            refund_transferred_to_payer: 0,
            redirected_principal: 0,
            treasury_surplus: 0,
            deposit_after: ch.deposit(),
            payout_after: ch.payout_watermark(),
            withdrawn_after: ch.payer_withdrawn_at(),
            refund_destination: *refund_destination.as_array(),
        })
    }

    pub fn actual(&mut self, channel: &AccountView) -> ProgramResult {
        let ch = Channel::from_account(channel)?;
        self.executed = 1;
        self.deposit_after = ch.deposit();
        self.payout_after = ch.payout_watermark();
        self.withdrawn_after = ch.payer_withdrawn_at();
        Ok(())
    }
}

pub fn finish(channel: &mut AccountView) -> ProgramResult {
    Channel::from_account_mut(channel)?.hooks.in_progress = 0;
    Ok(())
}

/// Exact account partition for the operation's pair, including disabled slots.
pub fn validate_tail(channel: &AccountView, tail: &[AccountView], first: usize) -> ProgramResult {
    let ch = Channel::from_account(channel)?;
    let count: usize = ch.hooks.descriptors[first..first + 2]
        .iter()
        .filter(|d| d.enabled())
        .map(|d| 2 + d.account_count as usize)
        .sum();
    if count != tail.len() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut offset = 0;
    for phase in first..first + 2 {
        let descriptor = &ch.hooks.descriptors[phase];
        if !descriptor.enabled() {
            continue;
        }
        let bundle = &tail[offset..offset + 2 + descriptor.account_count as usize];
        let (authority, _) = Address::find_program_address(
            &[
                AUTHORITY_SEED,
                channel.address().as_ref(),
                &ch.hooks.commitment,
                &[phase as u8],
                descriptor.program.as_ref(),
            ],
            &crate::ID,
        );
        if bundle[0].address() != &descriptor.program
            || !bundle[0].executable()
            || bundle[1].address() != &authority
        {
            return Err(ProgramError::InvalidAccountData);
        }
        for (meta, account) in descriptor.accounts[..descriptor.account_count as usize]
            .iter()
            .zip(&bundle[2..])
        {
            if account.address() != &meta.address
                || meta.address == *channel.address()
                || meta.address == authority
                || meta.address == descriptor.program
                || (meta.writable == 1 && !account.is_writable())
            {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        offset += bundle.len();
    }
    Ok(())
}

/// Only the scoped capability signs. Channel is always readonly, and no
/// transaction signer privilege is inherited by an additional account.
#[inline(never)]
pub fn invoke(
    channel: &AccountView,
    tail: &[AccountView],
    context: &HookContext,
    phase: usize,
) -> ProgramResult {
    let ch = Channel::from_account(channel)?;
    let first = phase & !1;
    let offset = if phase == first || !ch.hooks.descriptors[first].enabled() {
        0
    } else {
        2 + ch.hooks.descriptors[first].account_count as usize
    };
    let descriptor = ch.hooks.descriptors[phase];
    drop(ch);
    if !descriptor.enabled() {
        return Ok(());
    }
    let n = descriptor.account_count as usize;
    let bundle = tail
        .get(offset..offset + n + 2)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let program = &bundle[0];
    let authority = &bundle[1];
    let phase_bytes = [phase as u8];
    let (expected, bump) = Address::find_program_address(
        &[
            AUTHORITY_SEED,
            channel.address().as_ref(),
            &context.configuration,
            &phase_bytes,
            descriptor.program.as_ref(),
        ],
        &crate::ID,
    );
    if program.address() != &descriptor.program
        || !program.executable()
        || authority.address() != &expected
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut metas: [InstructionAccount<'_>; 6] =
        core::array::from_fn(|_| InstructionAccount::readonly(channel.address()));
    let mut infos = [channel; 7];
    metas[0] = InstructionAccount::readonly_signer(authority.address());
    metas[1] = InstructionAccount::readonly(channel.address());
    infos[0] = authority;
    infos[1] = channel;
    for i in 0..n {
        let account = &bundle[i + 2];
        let meta = descriptor.accounts[i];
        // Duplicate channel/capability/program entries can union privileges.
        if account.address() != &meta.address
            || meta.address == *channel.address()
            || meta.address == expected
            || meta.address == descriptor.program
            || (meta.writable != 0 && !account.is_writable())
        {
            return Err(ProgramError::InvalidAccountData);
        }
        metas[i + 2] = if meta.writable == 1 {
            InstructionAccount::writable(account.address())
        } else {
            InstructionAccount::readonly(account.address())
        };
        infos[i + 2] = account;
    }
    infos[n + 2] = program;
    let mut callback = *context;
    callback.phase = phase as u8;
    let mut data = EventBuf::<640>::new();
    data.write(&descriptor.entrypoint);
    callback
        .serialize(&mut data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    data.push(descriptor.static_len);
    data.write(&descriptor.static_context[..descriptor.static_len as usize]);
    let bump_bytes = [bump];
    let seeds = [
        Seed::from(AUTHORITY_SEED),
        Seed::from(channel.address().as_ref()),
        Seed::from(&context.configuration),
        Seed::from(&phase_bytes),
        Seed::from(descriptor.program.as_ref()),
        Seed::from(&bump_bytes),
    ];
    invoke_signed_with_bounds::<7, _>(
        &InstructionView {
            program_id: program.address(),
            accounts: &metas[..n + 2],
            data: data.as_slice(),
        },
        &infos[..n + 3],
        &[Signer::from(&seeds)],
    )
}

/// Reload canonical custody after every callback. Escrow balance may not
/// change inside hooks: donations are surplus, never credited principal.
pub fn revalidate(
    ctx: &ChannelContext<'_>,
    payer_ata: Option<&AccountView>,
    expected_escrow: u64,
) -> ProgramResult {
    let ch = Channel::from_account(&ctx.channel)?;
    ctx.channel_token_account
        .validate_as_ata_checked(ctx.channel.address(), &ctx.token_ctx)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if let Some(payer) = payer_ata {
        payer
            .validate_as_ata_checked(&ch.payer, &ctx.token_ctx)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    }
    if ctx
        .token_ctx
        .token_program
        .amount(&ctx.channel_token_account.as_any())?
        != expected_escrow
    {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

const _: () = {
    assert!(core::mem::size_of::<HookMeta>() == 33);
    assert!(core::mem::size_of::<HookDescriptor>() == 206);
    assert!(core::mem::size_of::<HookState>() == 865);
};

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn vector() -> Vec<u8> {
        let mut bytes = Vec::from([1]);
        bytes.extend_from_slice(&[8; 32]);
        bytes.extend_from_slice(b"prefund!");
        bytes.extend_from_slice(&[1, 2, 4, 5]);
        bytes.extend_from_slice(&[9; 32]);
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes
    }

    #[test]
    fn sparse_config_canonicalizes_and_commits_all_slots() {
        let state = HookState::parse(&vector()).unwrap();
        let mut fixed = [0; 824];
        fixed[..32].fill(8);
        fixed[32..40].copy_from_slice(b"prefund!");
        fixed[40] = 1;
        fixed[41] = 2;
        fixed[42..44].copy_from_slice(&[4, 5]);
        fixed[74..106].fill(9);
        fixed[106] = 1;
        assert_eq!(state.commitment, sha256(&fixed));
        assert_eq!(state.descriptors[0].static_context[2..], [0; 30]);
        assert!(!state.descriptors[1].enabled());
    }

    #[test]
    fn no_hooks_still_requires_four_explicit_slots() {
        assert!(HookState::parse(&[]).is_err());
        assert!(HookState::parse(&[0; 3]).is_err());
        assert!(HookState::parse(&[0; 5]).is_err());
        let state = HookState::parse(&[0; 4]).unwrap();
        assert!(!state.enabled());
        assert_eq!(state.commitment, sha256(&[0; 824]));
    }

    #[test]
    fn malformed_and_truncated_config_is_rejected() {
        let valid = vector();
        for end in 0..valid.len() {
            assert!(HookState::parse(&valid[..end]).is_err());
        }
        for (offset, value) in [(0, 2), (41, 5), (42, 33), (77, 2)] {
            let mut bytes = valid.clone();
            bytes[offset] = value;
            assert!(HookState::parse(&bytes).is_err(), "offset {offset}");
        }
        let mut bytes = valid;
        bytes.push(0);
        assert!(HookState::parse(&bytes).is_err());
    }

    #[test]
    fn zero_and_self_targets_are_rejected() {
        for target in [[0; 32], *crate::ID.as_array()] {
            let mut bytes = vector();
            bytes[1..33].copy_from_slice(&target);
            assert!(HookState::parse(&bytes).is_err());
        }
    }

    #[test]
    fn duplicate_accounts_are_rejected() {
        let mut bytes = vector();
        bytes[41] = 2;
        let duplicate = bytes[45..78].to_vec();
        bytes.splice(78..78, duplicate);
        assert!(HookState::parse(&bytes).is_err());
    }

    #[test]
    fn capability_domain_binds_phase_target_config_and_incarnation() {
        let state = HookState::parse(&vector()).unwrap();
        let channel = [2; 32];
        let target = [8; 32];
        let derive = |channel: &[u8], config: &[u8], phase: u8, target: &[u8]| {
            Address::find_program_address(
                &[AUTHORITY_SEED, channel, config, &[phase], target],
                &crate::ID,
            )
            .0
        };
        let authority = derive(&channel, &state.commitment, 0, &target);
        assert_ne!(authority, derive(&channel, &state.commitment, 1, &target));
        assert_ne!(authority, derive(&[3; 32], &state.commitment, 0, &target));
        assert_ne!(authority, derive(&channel, &[0; 32], 0, &target));
        assert_ne!(authority, derive(&channel, &state.commitment, 0, &[9; 32]));
    }

    #[test]
    fn state_offsets_are_pinned() {
        assert_eq!(core::mem::offset_of!(Channel, hooks), 256);
        assert_eq!(core::mem::offset_of!(HookState, sequence), 1);
        assert_eq!(core::mem::offset_of!(HookState, commitment), 9);
        assert_eq!(core::mem::offset_of!(HookState, descriptors), 41);
        assert_eq!(core::mem::offset_of!(HookDescriptor, accounts), 74);
    }

    #[test]
    fn callback_context_wire_size_is_pinned() {
        // All fields are integers and byte arrays, for which zero is valid.
        let context: HookContext = unsafe { core::mem::zeroed() };
        assert_eq!(borsh::object_length(&context).unwrap(), 428);
        let mut buffer = EventBuf::<640>::new();
        context.serialize(&mut buffer).unwrap();
        assert_eq!(buffer.as_slice().len(), 428);
    }
}
