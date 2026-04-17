//! Solana payment channels program.
//!
//! Unidirectional payment channels over SPL Token and Token-2022, built on
//! Pinocchio. Codama drives IDL + client generation.

use pinocchio::{AccountView, Address, ProgramResult, address::declare_id, error::ProgramError};

pinocchio::entrypoint!(process_instruction);

pub mod constants;
pub use constants::*;

pub mod errors;
pub use errors::*;

pub mod event_engine;
pub mod events;

pub mod instructions;
pub use instructions::*;

pub mod state;
pub use state::*;

#[cfg(test)]
pub mod tests;

declare_id!("GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc");

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (&discriminator, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match discriminator {
        open::DISCRIMINATOR => open::process(accounts, data),
        settle::DISCRIMINATOR => settle::process(accounts, data),
        top_up::DISCRIMINATOR => top_up::process(accounts, data),
        settle_and_finalize::DISCRIMINATOR => settle_and_finalize::process(accounts, data),
        request_close::DISCRIMINATOR => request_close::process(accounts, data),
        finalize::DISCRIMINATOR => finalize::process(accounts, data),
        distribute::DISCRIMINATOR => distribute::process(accounts, data),
        withdraw_payer::DISCRIMINATOR => withdraw_payer::process(accounts, data),
        withdraw_payee::DISCRIMINATOR => withdraw_payee::process(accounts, data),
        emit_event::DISCRIMINATOR => emit_event::process(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
