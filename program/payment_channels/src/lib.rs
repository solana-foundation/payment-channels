//! Solana payment channels program.
//!
//! Unidirectional payment channels over SPL Token and Token-2022, built on
//! Pinocchio. Codama drives IDL + client generation.

#![no_std]

#[cfg(all(feature = "idl", target_os = "solana"))]
compile_error!("the `idl` feature is host-only; do not enable it for SBF builds");

use pinocchio::{AccountView, Address, ProgramResult, address::declare_id};

pinocchio::program_entrypoint!(process_instruction);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

pub mod constants;
pub use constants::*;

pub mod errors;
pub use errors::*;

pub mod event_engine;
pub mod events;

pub mod instructions;
pub use instructions::helpers::ed25519;
pub use instructions::*;

pub mod state;
pub use state::*;

declare_id!("GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match PaymentChannelsInstruction::from_bytes(instruction_data)? {
        PaymentChannelsInstruction::Open(args) => open::process(program_id, accounts, &args),
        PaymentChannelsInstruction::Settle(args) => settle::process(program_id, accounts, args),
        PaymentChannelsInstruction::TopUp(args) => top_up::process(program_id, accounts, args),
        PaymentChannelsInstruction::SettleAndFinalize(args) => {
            settle_and_finalize::process(program_id, accounts, args)
        }
        PaymentChannelsInstruction::RequestClose => request_close::process(program_id, accounts),
        PaymentChannelsInstruction::Finalize => finalize::process(program_id, accounts),
        PaymentChannelsInstruction::Distribute(args) => {
            distribute::process(program_id, accounts, &args)
        }
        PaymentChannelsInstruction::WithdrawPayer => withdraw_payer::process(program_id, accounts),
        PaymentChannelsInstruction::EmitEvent => emit_event::process(program_id, accounts),
    }
}
