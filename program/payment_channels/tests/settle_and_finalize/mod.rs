mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::InstructionResult, result::ProgramResult};
use payment_channels::instructions::settle_and_finalize::DISCRIMINATOR;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader};

/// Execution descriptor for a single `settleAndFinalize` Mollusk run.
///
/// Construct with [`SettleAndFinalizeRun::new`] for the required fields;
/// override any public field via struct update syntax before calling
/// [`SettleAndFinalizeRun::run`].
pub(super) struct SettleAndFinalizeRun {
    pub merchant: Pubkey,
    pub is_signer: bool,
    pub channel_blob: Vec<u8>,
    /// `0` = no voucher; any other byte = apply the voucher carried by the
    /// bundled Ed25519 ix. These Mollusk runs wire no real precompile ix, so a
    /// non-zero value here exercises the missing-Ed25519 path, not a happy one.
    pub has_voucher: u8,
}

impl SettleAndFinalizeRun {
    pub fn new(merchant: Pubkey, channel_blob: Vec<u8>) -> Self {
        Self {
            merchant,
            is_signer: true,
            channel_blob,
            has_voucher: 0,
        }
    }

    pub fn run(self) -> ProgramResult {
        self.run_inspect().program_result
    }

    pub fn run_inspect(self) -> InstructionResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        // Wire layout: [discriminator(1)] [has_voucher(1)] = 2 bytes total. The
        // voucher itself (when applied) rides in the bundled Ed25519 ix.
        let ix_data = vec![DISCRIMINATOR, self.has_voucher];

        let ix = Instruction::new_with_bytes(
            PROGRAM_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(self.merchant, self.is_signer),
                AccountMeta::new(channel_pubkey, false),
                AccountMeta::new_readonly(Pubkey::new_unique(), false), // instructions_sysvar (unused for no-voucher)
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
