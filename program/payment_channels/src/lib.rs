//! Solana payment channels program.
//!
//! Unidirectional payment channels over SPL Token and Token-2022, built on
//! Pinocchio. Codama drives IDL + client generation.

#![no_std]

// Belt-and-suspenders: the `idl` feature pulls codama into the runtime
// dep graph, which drags in std via serde/toml/cargo_toml. That's fine
// for host-only IDL regen (`cargo build --features idl`), but is
// catastrophic for SBF builds — std's `panic_impl` lang item collides
// with `nostd_panic_handler!()` below (E0152). Fail loudly rather than
// letting a future `cargo build-sbf --features idl` silently break.
#[cfg(all(feature = "idl", target_os = "solana"))]
compile_error!("the `idl` feature is host-only; do not enable it for SBF builds");

use pinocchio::{AccountView, Address, ProgramResult, address::declare_id};

// `program_entrypoint!` (not `lazy_program_entrypoint!`): lazy's
// `InstructionContext::instruction_data()` errors until every account has
// been consumed via `next_account()`. That is incompatible with
// dispatch-by-leading-discriminator when per-instruction account counts
// vary, which is the case here.
pinocchio::program_entrypoint!(process_instruction);
pinocchio::no_allocator!();
// `nostd_panic_handler!` is safe here because codama is now an
// *optional* dep behind the `idl` feature (off by default; SBF builds
// never enable it). Without codama, no runtime dep pulls std, so this
// claims `panic_impl` without collision.
pinocchio::nostd_panic_handler!();

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

declare_id!("GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc");

fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match PaymentChannelsInstruction::from_bytes(instruction_data)? {
        PaymentChannelsInstruction::Open(args) => open::process(program_id, accounts, &args),
        PaymentChannelsInstruction::Settle(args) => settle::process(program_id, accounts, &args),
        PaymentChannelsInstruction::TopUp(args) => top_up::process(program_id, accounts, &args),
        PaymentChannelsInstruction::SettleAndFinalize(args) => {
            settle_and_finalize::process(program_id, accounts, &args)
        }
        PaymentChannelsInstruction::RequestClose => request_close::process(program_id, accounts),
        PaymentChannelsInstruction::Finalize => finalize::process(program_id, accounts),
        PaymentChannelsInstruction::Distribute(args) => {
            distribute::process(program_id, accounts, &args)
        }
        PaymentChannelsInstruction::WithdrawPayer => withdraw_payer::process(program_id, accounts),
        PaymentChannelsInstruction::WithdrawPayee => withdraw_payee::process(program_id, accounts),
        PaymentChannelsInstruction::EmitEvent => emit_event::process(program_id, accounts),
    }
}
