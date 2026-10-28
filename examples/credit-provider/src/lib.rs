//! Token-backed credit custody example for payment-channel V2 callbacks.
#![no_std]

#[cfg(feature = "client")]
extern crate alloc;

#[cfg(not(target_os = "solana"))]
extern crate std;

use borsh::{BorshDeserialize, BorshSerialize};
use payment_channel_interface::hooks::{
    HookContext, HookDescriptor, HookMeta, HookState, descriptor_commitment,
};
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process_instruction);
#[cfg(target_os = "solana")]
pinocchio::no_allocator!();
#[cfg(target_os = "solana")]
pinocchio::nostd_panic_handler!();

#[cfg(feature = "client")]
pub mod client;
mod processor;

pub const LEDGER_SEED: &[u8] = b"credit";
pub const CALLBACK_ENTRYPOINT: [u8; 8] = *b"credit!!";
pub const INITIALIZE: u8 = 0;
pub const DEPOSIT: u8 = 1;
pub const AUTHORIZE: u8 = 2;
pub const CANCEL_UNFUNDED: u8 = 3;
pub const LOADER: Address = solana_address::address!("BPFLoaderUpgradeab1e11111111111111111111111");

/// Both the credit owner and the stored issuer must sign this exact instruction.
/// A nonce is consumed once; there is no active-channel renewal operation.
#[derive(Clone, Copy, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct Authorization {
    pub payee: [u8; 32],
    pub authorized_signer: [u8; 32],
    pub distribution_hash: [u8; 32],
    pub salt: u64,
    pub open_slot: u64,
    pub cap: u64,
    pub nonce: u64,
    pub expires_at_slot: u64,
}

/// Borsh, fixed size, owned exclusively by this example program.
#[derive(Clone, Copy, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct Ledger {
    pub version: u8,
    pub busy: bool,
    pub active: bool,
    pub owner: [u8; 32],
    pub mint: [u8; 32],
    pub issuer: [u8; 32],
    pub channel: [u8; 32],
    pub authorization: Authorization,
    pub configuration: [u8; 32],
    pub credits: u64,
    pub funded: u64,
    pub refunded: u64,
    pub last_sequence: u64,
}

impl Ledger {
    pub const LEN: usize = 331;
}

pub fn ledger_address(program: &Address, owner: &Address, mint: &Address) -> (Address, u8) {
    Address::find_program_address(&[LEDGER_SEED, owner.as_ref(), mint.as_ref()], program)
}

pub fn ata_address(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(
        &[owner.as_ref(), pinocchio_token::ID.as_ref(), mint.as_ref()],
        &pinocchio_associated_token_account::ID,
    )
    .0
}

/// The complete, immutable hook policy: no caller-selected hooks or extra accounts.
pub fn hook_state(program: &Address, owner: &Address, mint: &Address) -> HookState {
    let ledger = ledger_address(program, owner, mint).0;
    let accounts = [
        HookMeta {
            address: ledger,
            writable: 1,
        },
        HookMeta {
            address: ata_address(&ledger, mint),
            writable: 1,
        },
        HookMeta {
            address: ata_address(owner, mint),
            writable: 1,
        },
        HookMeta {
            address: pinocchio_token::ID,
            writable: 0,
        },
    ];
    let descriptor = HookDescriptor {
        program: *program,
        entrypoint: CALLBACK_ENTRYPOINT,
        account_count: accounts.len() as u8,
        static_len: 0,
        static_context: [0; 32],
        accounts,
    };
    let mut state = HookState::EMPTY;
    state.descriptors[0] = descriptor;
    state.descriptors[3] = descriptor;
    state.commitment = descriptor_commitment(&state.descriptors);
    state
}

/// Decode the shared ABI; the processor additionally validates CPI provenance.
pub fn decode_callback(data: &[u8]) -> Result<HookContext, ProgramError> {
    let context = HookContext::decode_callback(data, &CALLBACK_ENTRYPOINT, &[])?;
    if !matches!(context.phase, 0 | 3) {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(context)
}

pub fn process_instruction(
    program: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if data.starts_with(&CALLBACK_ENTRYPOINT) {
        return processor::callback(program, accounts, data);
    }
    match data.split_first() {
        Some((&INITIALIZE, [])) => processor::initialize(program, accounts),
        Some((&DEPOSIT, bytes)) => processor::deposit(
            program,
            accounts,
            u64::try_from_slice(bytes).map_err(|_| ProgramError::InvalidInstructionData)?,
        ),
        Some((&AUTHORIZE, bytes)) => processor::authorize(
            program,
            accounts,
            Authorization::try_from_slice(bytes)
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ),
        Some((&CANCEL_UNFUNDED, [])) => processor::cancel_unfunded(program, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
