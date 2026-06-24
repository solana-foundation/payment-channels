mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::InstructionResult, result::ProgramResult};
use payment_channels::instructions::settle::DISCRIMINATOR;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader};

/// Execution descriptor for a single `settle` Mollusk run.
///
/// Construct with [`SettleRun::new`]; call [`SettleRun::run`] to execute.
///
/// These tests exercise the pre-`verify_voucher` guards (status, owner,
/// discriminator, version), which fire before the Instructions sysvar is read,
/// so this harness wires a dummy account at that slot and the `settle`
/// instruction carries no data beyond its discriminator. Tests that need a
/// real Ed25519 precompile ix live in `e2e.rs` under LiteSVM.
pub(super) struct SettleRun {
    pub channel_blob: Vec<u8>,
}

impl SettleRun {
    pub fn new(channel_blob: Vec<u8>) -> Self {
        Self { channel_blob }
    }

    pub fn run(self) -> ProgramResult {
        self.run_inspect().program_result
    }

    pub fn run_inspect(self) -> InstructionResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        // `settle` carries no data beyond its discriminator; the voucher rides
        // in the (here-absent) bundled Ed25519 ix, which these pre-sysvar guard
        // tests never reach.
        let ix_data = vec![DISCRIMINATOR];

        let ix = Instruction::new_with_bytes(
            PROGRAM_ID,
            &ix_data,
            vec![
                AccountMeta::new(channel_pubkey, false),
                // Pre-`verify_voucher` guards reject before the sysvar is read,
                // so a unique-pubkey dummy sidesteps Mollusk's special handling
                // of `Sysvar1nstructions…`.
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
            ],
        );

        let channel_account = Account {
            lamports: 10_000_000,
            data: self.channel_blob,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };
        let dummy = Account {
            lamports: 1_000_000,
            ..Default::default()
        };

        let accounts: Vec<(Pubkey, Account)> = ix
            .accounts
            .iter()
            .map(|m| {
                let acc = if m.pubkey == channel_pubkey {
                    channel_account.clone()
                } else {
                    dummy.clone()
                };
                (m.pubkey, acc)
            })
            .collect();

        mollusk.process_instruction(&ix, &accounts)
    }
}
