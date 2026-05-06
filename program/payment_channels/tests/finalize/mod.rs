mod e2e;
mod integration;

use mollusk_svm::{
    Mollusk,
    result::{InstructionResult, ProgramResult},
};
use payment_channels_core::instructions::finalize::DISCRIMINATOR;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader};

/// Execution descriptor for a single `finalize` Mollusk run.
///
/// Construct with [`FinalizeRun::new`] for the required fields; override any
/// public field via struct update syntax before calling [`FinalizeRun::run`].
pub(super) struct FinalizeRun {
    pub channel_blob: Vec<u8>,
}

impl FinalizeRun {
    pub fn new(channel_blob: Vec<u8>) -> Self {
        Self { channel_blob }
    }

    pub fn run(self) -> ProgramResult {
        self.run_inspect().program_result
    }

    pub fn run_inspect(self) -> InstructionResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        let ix = Instruction::new_with_bytes(
            PROGRAM_ID,
            &[DISCRIMINATOR],
            vec![AccountMeta::new(channel_pubkey, false)],
        );

        let channel_account = Account {
            lamports: 10_000_000,
            data: self.channel_blob,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };

        mollusk.process_instruction(&ix, &[(channel_pubkey, channel_account)])
    }
}
