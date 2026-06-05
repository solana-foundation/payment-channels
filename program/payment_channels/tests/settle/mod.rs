mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::InstructionResult, result::ProgramResult};
use payment_channels::instructions::settle::DISCRIMINATOR;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader, voucher::TEST_CHAIN_ID};

/// Execution descriptor for a single `settle` Mollusk run.
///
/// Construct with [`SettleRun::new`] for the required fields; override any
/// public field via struct update syntax before calling [`SettleRun::run`].
///
/// Pre-`verify_voucher` guards (status, owner, discriminator, version) fire
/// before the Instructions sysvar is read, so this harness wires a dummy
/// account at that slot. Tests that need a real Ed25519 precompile ix live
/// in `e2e.rs` under LiteSVM.
pub(super) struct SettleRun {
    pub channel_blob: Vec<u8>,
    /// Voucher `channel_id` field (32 bytes).
    pub voucher_channel_id: Pubkey,
    pub voucher_cumulative_amount: u64,
    pub voucher_expires_at: i64,
    /// Voucher `chain_id` field (32 bytes). Defaults to this cluster's
    /// `CHAIN_ID`; only the byte length matters for the pre-`verify_voucher`
    /// guards this harness exercises.
    pub voucher_chain_id: Pubkey,
}

impl SettleRun {
    pub fn new(channel_blob: Vec<u8>) -> Self {
        Self {
            channel_blob,
            voucher_channel_id: Pubkey::default(),
            voucher_cumulative_amount: 0,
            voucher_expires_at: 0,
            voucher_chain_id: TEST_CHAIN_ID,
        }
    }

    pub fn run(self) -> ProgramResult {
        self.run_inspect().program_result
    }

    pub fn run_inspect(self) -> InstructionResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        // Wire layout: [discriminator(1)] [channel_id(32)] [cumulative(8)]
        //              [expires_at(8)] [chain_id(32)] = 81 bytes total.
        let mut ix_data = vec![DISCRIMINATOR];
        ix_data.extend_from_slice(self.voucher_channel_id.as_ref());
        ix_data.extend_from_slice(&self.voucher_cumulative_amount.to_le_bytes());
        ix_data.extend_from_slice(&self.voucher_expires_at.to_le_bytes());
        ix_data.extend_from_slice(self.voucher_chain_id.as_ref());

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
