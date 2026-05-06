//! `withdraw_payer` instruction test suite.
//!
//! Two tiers:
//! - [`integration`]: Mollusk-driven guard/state-validation tests built on top
//!   of `WithdrawPayerRun` + [`ChannelBuilder`](crate::common::ChannelBuilder).
//! - [`e2e`]: full LiteSVM scenarios that drive `open` → patch-to-FINALIZED →
//!   `withdraw_payer` against the compiled `.so` and assert real token balances.

mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels_core::{instructions::withdraw_payer::DISCRIMINATOR, state::Channel};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader, SPL_TOKEN};

/// Execution descriptor for a single `withdrawPayer` Mollusk run.
///
/// Construct with [`WithdrawPayerRun::new`] for the required fields; override
/// any public field via struct update syntax before calling [`WithdrawPayerRun::run`].
pub(super) struct WithdrawPayerRun {
    pub payer: Pubkey,
    /// Whether `payer` is marked as a signer in the account metas.
    pub is_signer: bool,
    pub channel_blob: Vec<u8>,
    pub channel_ata: Pubkey,
    pub payer_ata: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
}

impl WithdrawPayerRun {
    pub fn new(payer: Pubkey, channel_blob: Vec<u8>) -> Self {
        Self {
            payer,
            is_signer: true,
            channel_blob,
            channel_ata: Pubkey::new_unique(),
            payer_ata: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            token_program: SPL_TOKEN,
        }
    }

    pub fn run(self) -> ProgramResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        let ix = Instruction::new_with_bytes(
            PROGRAM_ID,
            &[DISCRIMINATOR],
            vec![
                AccountMeta::new_readonly(self.payer, self.is_signer),
                AccountMeta::new(channel_pubkey, false),
                AccountMeta::new(self.channel_ata, false),
                AccountMeta::new(self.payer_ata, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new_readonly(self.token_program, false),
            ],
        );

        let channel_account = Account {
            lamports: 10_000_000,
            data: if self.channel_blob.is_empty() {
                vec![0u8; Channel::LEN]
            } else {
                self.channel_blob
            },
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
