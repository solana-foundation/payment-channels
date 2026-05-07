//! `distribute` instruction test suite.
//!
//! Two tiers:
//! - [`integration`]: Mollusk-driven argument/state-validation tests built
//!   on top of `DistributeRun` + [`ChannelBuilder`](crate::common::ChannelBuilder).
//! - [`e2e`]: full LiteSVM scenarios that drive `open` → optional `settle` →
//!   `distribute` against the compiled `.so` and assert real token balances.

mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels::state::Channel;
use payment_channels_client::instructions::{Distribute, DistributeInstructionArgs};
use payment_channels_client::types::{DistributeArgs, DistributionEntry};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader, SPL_TOKEN, TOKEN_2022};

pub(super) const STATUS_OPEN: u8 = 0;
pub(super) const STATUS_FINALIZED: u8 = 1;
pub(super) const STATUS_CLOSING: u8 = 2;
pub(super) const MAX_DISTRIBUTION_RECIPIENTS: usize = 32;

/// Recipient + share for the distribution plan committed at `open` and
/// re-presented at `distribute`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Split {
    pub owner: Pubkey,
    pub bps: u16,
}

/// `constants::TREASURY_OWNER` mirror — alternating `0xBE 0xEF` × 16.
pub(super) fn treasury_owner() -> Pubkey {
    let mut b = [0u8; 32];
    for i in 0..16 {
        b[i * 2] = 0xBE;
        b[i * 2 + 1] = 0xEF;
    }
    Pubkey::new_from_array(b)
}

/// Builds the u32-prefixed recipient vector accepted by the generated client.
pub(super) fn build_recipients(splits: &[Split]) -> Vec<DistributionEntry> {
    splits
        .iter()
        .map(|s| DistributionEntry {
            recipient: Address::from(s.owner.to_bytes()),
            bps: s.bps,
        })
        .collect()
}

/// Full distribute ix build with the 8-slot fixed head + dynamic recipient tail.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_distribute_ix(
    channel: &Pubkey,
    payer: &Pubkey,
    channel_ata: &Pubkey,
    payer_ata: &Pubkey,
    payee_ata: &Pubkey,
    treasury_ata: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    recipient_atas: &[Pubkey],
    recipients: Vec<DistributionEntry>,
) -> Instruction {
    let remaining: Vec<AccountMeta> = recipient_atas
        .iter()
        .map(|a| AccountMeta::new(*a, false))
        .collect();
    let accounts = Distribute {
        channel: Address::from(channel.to_bytes()),
        payer: Address::from(payer.to_bytes()),
        channel_token_account: Address::from(channel_ata.to_bytes()),
        payer_token_account: Address::from(payer_ata.to_bytes()),
        payee_token_account: Address::from(payee_ata.to_bytes()),
        treasury_token_account: Address::from(treasury_ata.to_bytes()),
        mint: Address::from(mint.to_bytes()),
        token_program: Address::from(token_program.to_bytes()),
    };
    accounts.instruction_with_remaining_accounts(
        DistributeInstructionArgs {
            distribute_args: DistributeArgs { recipients },
        },
        &remaining,
    )
}

/// Mollusk execution descriptor for a single `distribute` run. Override
/// any public field via struct-update syntax before calling [`run`].
pub(super) struct DistributeRun {
    pub channel: Pubkey,
    pub channel_blob: Vec<u8>,
    pub payer: Pubkey,
    pub channel_ata: Pubkey,
    pub payer_ata: Pubkey,
    pub payee_ata: Pubkey,
    pub treasury_ata: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub recipient_atas: Vec<Pubkey>,
    pub recipients: Vec<DistributionEntry>,
}

impl DistributeRun {
    /// Construct with a channel blob + a single dummy split; override any
    /// field on the way to `run()`.
    pub fn new(channel_blob: Vec<u8>, payer: Pubkey, splits: &[Split]) -> Self {
        Self {
            channel: Pubkey::new_unique(),
            channel_blob,
            payer,
            channel_ata: Pubkey::new_unique(),
            payer_ata: Pubkey::new_unique(),
            payee_ata: Pubkey::new_unique(),
            treasury_ata: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            token_program: SPL_TOKEN,
            recipient_atas: splits.iter().map(|_| Pubkey::new_unique()).collect(),
            recipients: build_recipients(splits),
        }
    }

    pub fn run(self) -> ProgramResult {
        let mollusk = Mollusk::load_program();

        let ix = build_distribute_ix(
            &self.channel,
            &self.payer,
            &self.channel_ata,
            &self.payer_ata,
            &self.payee_ata,
            &self.treasury_ata,
            &self.mint,
            &self.token_program,
            &self.recipient_atas,
            self.recipients,
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
                let acc = if m.pubkey == self.channel {
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
