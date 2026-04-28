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
use payment_channels::instructions::distribute::DISCRIMINATOR;
use payment_channels::state::Channel;
use payment_channels_client::types::{DistributeArgs, DistributionEntry, DistributionRecipients};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, pubkey};

use crate::common::{PROGRAM_ID, ProgramLoader};

pub(super) const TOKEN_2022: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
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

/// Build a typed `DistributionRecipients` from `splits`. Trailing entries
/// are zeroed; `count` is set to `splits.len()` (mutate post-hoc to drive
/// the count guard in `validate()`).
pub(super) fn build_recipients(splits: &[Split]) -> DistributionRecipients {
    let mut entries: [DistributionEntry; MAX_DISTRIBUTION_RECIPIENTS] =
        std::array::from_fn(|_| DistributionEntry {
            recipient: Address::from([0u8; 32]),
            bps: 0,
        });
    for (i, s) in splits.iter().enumerate() {
        entries[i] = DistributionEntry {
            recipient: Address::from(s.owner.to_bytes()),
            bps: s.bps,
        };
    }
    DistributionRecipients {
        count: splits.len() as u8,
        entries,
    }
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
    recipients: DistributionRecipients,
) -> Instruction {
    let args = DistributeArgs { recipients };
    let remaining: Vec<AccountMeta> = recipient_atas
        .iter()
        .map(|a| AccountMeta::new(*a, false))
        .collect();
    let base = payment_channels_client::instructions::Distribute {
        channel: *channel,
        payer: *payer,
        channel_token_account: *channel_ata,
        payer_token_account: *payer_ata,
        payee_token_account: *payee_ata,
        treasury_token_account: *treasury_ata,
        mint: *mint,
        token_program: *token_program,
    };
    base.instruction_with_remaining_accounts(
        payment_channels_client::instructions::DistributeInstructionArgs {
            distribute_args: args,
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
    pub recipients: DistributionRecipients,
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
            token_program: Pubkey::new_unique(),
            recipient_atas: splits.iter().map(|_| Pubkey::new_unique()).collect(),
            recipients: build_recipients(splits),
        }
    }

    pub fn run(self) -> ProgramResult {
        let mollusk = Mollusk::load_program();

        // Borsh-encode the args manually so we don't pay the full
        // `payment_channels_client::Distribute` builder dance just to
        // produce the data payload here.
        let args = DistributeArgs {
            recipients: self.recipients.clone(),
        };
        let mut ix_data = vec![DISCRIMINATOR];
        let args_bytes = borsh::to_vec(&args).expect("borsh encode");
        ix_data.extend_from_slice(&args_bytes);

        let mut metas = vec![
            AccountMeta::new(self.channel, false),
            AccountMeta::new(self.payer, false),
            AccountMeta::new(self.channel_ata, false),
            AccountMeta::new(self.payer_ata, false),
            AccountMeta::new(self.payee_ata, false),
            AccountMeta::new(self.treasury_ata, false),
            AccountMeta::new_readonly(self.mint, false),
            AccountMeta::new_readonly(self.token_program, false),
        ];
        metas.extend(
            self.recipient_atas
                .iter()
                .map(|a| AccountMeta::new(*a, false)),
        );

        let ix = Instruction::new_with_bytes(PROGRAM_ID, &ix_data, metas);

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
