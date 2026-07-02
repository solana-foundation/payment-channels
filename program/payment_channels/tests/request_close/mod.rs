mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::InstructionResult, result::ProgramResult};
use payment_channels::instructions::request_close::{DISCRIMINATOR, RequestCloseArgs};
use payment_channels::state::Transmutable;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader};

/// Execution descriptor for a single `requestClose` Mollusk run.
///
/// Construct with [`RequestCloseRun::new`] for the required fields;
/// override any public field via struct update syntax before calling
/// [`RequestCloseRun::run`].
pub(super) struct RequestCloseRun {
    pub payer: Pubkey,
    /// Whether `payer` is marked as a signer in the account metas.
    pub is_signer: bool,
    pub channel_blob: Vec<u8>,
    pub expected_open_slot: u64,
    /// Appended after the fixed account metas. The handler's exact-slice
    /// destructure must reject any non-empty value.
    pub extra_accounts: Vec<AccountMeta>,
}

impl RequestCloseRun {
    pub fn new(payer: Pubkey, channel_blob: Vec<u8>) -> Self {
        Self {
            payer,
            is_signer: true,
            channel_blob,
            expected_open_slot: 0,
            extra_accounts: Vec::new(),
        }
    }

    pub fn run(self) -> ProgramResult {
        self.run_inspect().program_result
    }

    pub fn run_inspect(self) -> InstructionResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        let mut metas = vec![
            AccountMeta::new_readonly(self.payer, self.is_signer),
            AccountMeta::new(channel_pubkey, false),
        ];
        metas.extend(self.extra_accounts.iter().cloned());
        let mut ix_data = vec![DISCRIMINATOR];
        ix_data.extend_from_slice(
            RequestCloseArgs {
                expected_open_slot: self.expected_open_slot.to_le_bytes(),
            }
            .as_bytes(),
        );
        let ix = Instruction::new_with_bytes(PROGRAM_ID, &ix_data, metas);

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
