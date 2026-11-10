//! Frozen V2 lifecycle ABI. Phase and operation tags are economic tags, not
//! the discriminators of the newer `*WithHooks` instruction entrypoints.
use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::{Address, error::ProgramError};

pub const MAX_HOOK_ACCOUNTS: usize = 4;
pub const MAX_STATIC_CONTEXT: usize = 32;
pub const AUTHORITY_SEED: &[u8] = b"channel_hook";
pub const HOOK_CONTEXT_LEN: usize = 428;
pub const DESCRIPTORS_LEN: usize = 824;
const ZERO: Address = Address::new_from_array([0; 32]);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    PreFund = 0,
    PostFund = 1,
    PreDistribute = 2,
    PostDistribute = 3,
}

impl TryFrom<u8> for Phase {
    type Error = ProgramError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PreFund),
            1 => Ok(Self::PostFund),
            2 => Ok(Self::PreDistribute),
            3 => Ok(Self::PostDistribute),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Open = 1,
    TopUp = 3,
    Distribute = 7,
    WithdrawPayer = 8,
}

impl TryFrom<u8> for Operation {
    type Error = ProgramError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Open),
            3 => Ok(Self::TopUp),
            7 => Ok(Self::Distribute),
            8 => Ok(Self::WithdrawPayer),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookMeta {
    pub address: Address,
    pub writable: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Sparse open encoding for the default deployment.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProgramError> {
        Self::parse_for_program(bytes, &crate::ID)
    }

    /// Sparse open encoding; unused storage is canonical zero padding.
    pub fn parse_for_program(
        mut bytes: &[u8],
        channel_program: &Address,
    ) -> Result<Self, ProgramError> {
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
                || descriptor.program == *channel_program
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
        state.commitment = descriptor_commitment(&state.descriptors);
        Ok(state)
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], ProgramError> {
    let value = bytes.get(..N).ok_or(ProgramError::InvalidInstructionData)?;
    let mut out = [0; N];
    out.copy_from_slice(value);
    *bytes = &bytes[N..];
    Ok(out)
}

/// Commits all four fixed slots, including unused accounts and zero padding.
pub fn descriptor_commitment(descriptors: &[HookDescriptor; 4]) -> [u8; 32] {
    // SAFETY: repr(C), alignment one, only byte arrays/Address/u8, no padding.
    let bytes =
        unsafe { core::slice::from_raw_parts(descriptors.as_ptr().cast(), DESCRIPTORS_LEN) };
    crate::sha256(bytes)
}

pub fn hook_authority(
    channel_program: &Address,
    channel: &Address,
    configuration: &[u8; 32],
    phase: Phase,
    target: &Address,
) -> (Address, u8) {
    Address::find_program_address(
        &[
            AUTHORITY_SEED,
            channel.as_ref(),
            configuration,
            &[phase as u8],
            target.as_ref(),
        ],
        channel_program,
    )
}

/// Callback payload after the committed eight-byte entrypoint. Borsh/LE,
/// without enum tags or padding beyond these explicitly declared fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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
    /// Decode the entire callback envelope against a trusted entrypoint/static
    /// context. This only decodes; use the callback validator before acting.
    pub fn decode_callback(
        data: &[u8],
        entrypoint: &[u8; 8],
        static_context: &[u8],
    ) -> Result<Self, ProgramError> {
        if static_context.len() > MAX_STATIC_CONTEXT
            || data.len() != 8 + HOOK_CONTEXT_LEN + 1 + static_context.len()
            || data.get(..8) != Some(entrypoint)
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let context = Self::try_from_slice(&data[8..8 + HOOK_CONTEXT_LEN])
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if context.abi_version != 1
            || data[8 + HOOK_CONTEXT_LEN] as usize != static_context.len()
            || &data[9 + HOOK_CONTEXT_LEN..] != static_context
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(context)
    }
}

const _: () = {
    assert!(core::mem::size_of::<HookMeta>() == 33);
    assert!(core::mem::size_of::<HookDescriptor>() == 206);
    assert!(core::mem::size_of::<HookState>() == 865);
    assert!(core::mem::align_of::<HookState>() == 1);
};
