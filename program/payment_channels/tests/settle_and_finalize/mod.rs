mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::InstructionResult, result::ProgramResult};
use payment_channels_core::instructions::settle_and_finalize::DISCRIMINATOR;
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
    /// `0` = no voucher; any other byte = apply voucher bytes below.
    pub has_voucher: u8,
    /// Voucher `channel_id` field (32 bytes). Ignored when `has_voucher == 0`.
    pub voucher_channel_id: Pubkey,
    pub voucher_cumulative_amount: u64,
    pub voucher_expires_at: i64,
}

impl SettleAndFinalizeRun {
    pub fn new(merchant: Pubkey, channel_blob: Vec<u8>) -> Self {
        Self {
            merchant,
            is_signer: true,
            channel_blob,
            has_voucher: 0,
            voucher_channel_id: Pubkey::default(),
            voucher_cumulative_amount: 0,
            voucher_expires_at: 0,
        }
    }

    pub fn run(self) -> ProgramResult {
        self.run_inspect().program_result
    }

    pub fn run_inspect(self) -> InstructionResult {
        let mollusk = Mollusk::load_program();
        let channel_pubkey = Pubkey::new_unique();

        // Wire layout: [discriminator(1)] [channel_id(32)] [cumulative(8)]
        //              [expires_at(8)] [has_voucher(1)] = 50 bytes total.
        let mut ix_data = vec![DISCRIMINATOR];
        ix_data.extend_from_slice(self.voucher_channel_id.as_ref());
        ix_data.extend_from_slice(&self.voucher_cumulative_amount.to_le_bytes());
        ix_data.extend_from_slice(&self.voucher_expires_at.to_le_bytes());
        ix_data.push(self.has_voucher);

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
