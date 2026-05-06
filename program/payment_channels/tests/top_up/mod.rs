mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels_core::{
    instructions::top_up::{DISCRIMINATOR, TopUpArgs},
    state::Transmutable,
};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader, SPL_TOKEN};

pub(super) const DEPOSIT: u64 = 1_000_000;

/// Execution descriptor for a single `topUp` Mollusk run.
///
/// Construct with [`TopUpRun::new`] for the required fields; override any
/// public field via struct update syntax before calling [`TopUpRun::run`].
pub(super) struct TopUpRun {
    pub payer: Pubkey,
    /// Whether `payer` is marked as a signer in the account metas.
    pub is_signer: bool,
    pub channel_blob: Vec<u8>,
    /// Mint pubkey passed as account 4. Defaults to a random pubkey.
    pub mint: Pubkey,
    /// Channel token account pubkey passed as account 3. Defaults to a random pubkey.
    pub channel_ata: Pubkey,
    /// Token program pubkey passed as account 5. Defaults to SPL Token;
    /// override only when targeting the unknown-program dispatch arm.
    pub token_program: Pubkey,
    pub amount: u64,
}

impl TopUpRun {
    pub fn new(payer: Pubkey, channel_blob: Vec<u8>, amount: u64) -> Self {
        Self {
            payer,
            is_signer: true,
            channel_blob,
            mint: Pubkey::new_unique(),
            channel_ata: Pubkey::new_unique(),
            token_program: SPL_TOKEN,
            amount,
        }
    }

    pub fn run(self) -> ProgramResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        let mut ix_data = vec![DISCRIMINATOR];
        ix_data.extend_from_slice(
            TopUpArgs {
                amount: self.amount.to_le_bytes(),
            }
            .as_bytes(),
        );

        let ix = Instruction::new_with_bytes(
            PROGRAM_ID,
            &ix_data,
            vec![
                AccountMeta::new(self.payer, self.is_signer),
                AccountMeta::new(channel_pubkey, false),
                AccountMeta::new(Pubkey::new_unique(), false), // payer_token_account
                AccountMeta::new(self.channel_ata, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new_readonly(self.token_program, false),
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

        mollusk.process_instruction(&ix, &accounts).program_result
    }
}
