mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels::event_engine::EMIT_EVENT_IX_DISC;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader};

/// Execution descriptor for a single `emit_event` Mollusk run. The discriminator
/// is `EMIT_EVENT_IX_DISC = 228` and the only ix data is that one byte.
///
/// Construct with [`EmitEventRun::new`] for the standard "PDA signer, no
/// extras" shape; override fields via struct update syntax to exercise each
/// pre-CPI guard.
pub(super) struct EmitEventRun {
    pub authority: Pubkey,
    pub is_signer: bool,
    /// Extra readonly account metas appended after the authority — drives the
    /// slice-pattern arity check on the wrong-too-many side.
    pub extra_accounts: Vec<Pubkey>,
    /// When `false`, the ix is built with an empty `accounts` vec — drives the
    /// arity check on the wrong-too-few side.
    pub include_authority: bool,
}

impl EmitEventRun {
    pub fn new(authority: Pubkey) -> Self {
        Self {
            authority,
            is_signer: true,
            extra_accounts: Vec::new(),
            include_authority: true,
        }
    }

    pub fn run(self) -> ProgramResult {
        let mollusk = Mollusk::load_program();

        let mut accounts = if self.include_authority {
            vec![AccountMeta {
                pubkey: self.authority,
                is_signer: self.is_signer,
                is_writable: false,
            }]
        } else {
            Vec::new()
        };
        for extra in &self.extra_accounts {
            accounts.push(AccountMeta::new_readonly(*extra, false));
        }

        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts,
            data: vec![EMIT_EVENT_IX_DISC],
        };

        let dummy = Account {
            lamports: 1_000_000,
            ..Default::default()
        };
        let metas: Vec<(Pubkey, Account)> = ix
            .accounts
            .iter()
            .map(|m| (m.pubkey, dummy.clone()))
            .collect();

        mollusk.process_instruction(&ix, &metas).program_result
    }
}
