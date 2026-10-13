//! Solana payment channels program.
//!
//! Unidirectional payment channels over SPL Token and Token-2022, built on
//! Pinocchio. Codama drives IDL + client generation.

#![no_std]

#[cfg(all(feature = "no-entrypoint", not(target_os = "solana")))]
extern crate std;

#[cfg(feature = "idl")]
extern crate alloc;

#[cfg(all(feature = "idl", target_os = "solana"))]
compile_error!("the `idl` feature is host-only; do not enable it for SBF builds");

use pinocchio::{AccountView, Address, ProgramResult, address::declare_id};

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process_instruction);
#[cfg(any(not(feature = "no-entrypoint"), target_os = "solana"))]
pinocchio::no_allocator!();
#[cfg(any(not(feature = "no-entrypoint"), target_os = "solana"))]
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

mod hook_guard;
pub mod hooks;

#[cfg(not(feature = "devnet-deployment"))]
declare_id!("CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX");
#[cfg(feature = "devnet-deployment")]
declare_id!("CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ");

#[cfg_attr(feature = "no-entrypoint", allow(dead_code))]
fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    // Check all supplied channel accounts, including aliases. Internal operation
    // code can load guarded state, but no callback may start another entrypoint.
    hooks::check_entry(accounts)?;
    match PaymentChannelsInstruction::from_bytes(instruction_data)? {
        PaymentChannelsInstruction::Open(args) => open::process(program_id, accounts, &args),
        PaymentChannelsInstruction::OpenWithHooks(args) => {
            open::process(program_id, accounts, &args)
        }
        PaymentChannelsInstruction::TopUpWithHooks(args) => {
            top_up::process_with_hooks(program_id, accounts, args)
        }
        PaymentChannelsInstruction::DistributeWithHooks(args) => {
            distribute::process_with_hooks(program_id, accounts, &args)
        }
        PaymentChannelsInstruction::WithdrawPayerWithHooks => {
            withdraw_payer::process_with_hooks(program_id, accounts)
        }
        PaymentChannelsInstruction::Settle => settle::process(program_id, accounts),
        PaymentChannelsInstruction::TopUp(args) => top_up::process(program_id, accounts, args),
        PaymentChannelsInstruction::SettleAndSeal(args) => {
            settle_and_seal::process(program_id, accounts, args)
        }
        PaymentChannelsInstruction::RequestClose => request_close::process(program_id, accounts),
        PaymentChannelsInstruction::Seal => seal::process(program_id, accounts),
        PaymentChannelsInstruction::Distribute(args) => {
            distribute::process(program_id, accounts, &args)
        }
        PaymentChannelsInstruction::WithdrawPayer => withdraw_payer::process(program_id, accounts),
        PaymentChannelsInstruction::Reclaim => reclaim::process(program_id, accounts),
        PaymentChannelsInstruction::EmitEvent => emit_event::process(program_id, accounts),
    }
}
