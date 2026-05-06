//! Solana payment channels deployable program entrypoint.
//!
//! The Rust-linkable program API lives in `payment_channels_core`; this
//! crate intentionally remains cdylib-only so SBF builds can apply LTO.

#![no_std]

#[cfg(all(feature = "idl", target_os = "solana"))]
compile_error!("the `idl` feature is host-only; do not enable it for SBF builds");

use pinocchio::{AccountView, Address, ProgramResult};

pinocchio::program_entrypoint!(process_instruction);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    payment_channels_core::process_instruction(program_id, accounts, instruction_data)
}
