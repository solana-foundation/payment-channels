//! `reclaim` instruction test suite.
//!
//! Two tiers:
//! - [`integration`]: Mollusk-driven guard tests over planted channel blobs
//!   built with [`ChannelBuilder`](crate::common::ChannelBuilder).
//! - [`e2e`]: full LiteSVM scenarios driving the two-phase terminal close —
//!   ungated SEALED `distribute` (every token leg paid immediately, the
//!   channel left `Distributed`) followed by the slot-gated `reclaim` that frees
//!   the PDA rent.

mod e2e;
mod integration;

use mollusk_svm::{Mollusk, result::InstructionResult, result::ProgramResult};
use solana_account::Account;
use solana_pubkey::Pubkey;

use crate::common::{PROGRAM_ID, ProgramLoader, build_reclaim_ix};

/// Execution descriptor for a single `reclaim` Mollusk run.
///
/// Construct with [`ReclaimRun::new`]; override any public field via struct
/// update syntax before calling [`ReclaimRun::run`] /
/// [`ReclaimRun::run_inspect`].
pub(super) struct ReclaimRun {
    pub channel_blob: Vec<u8>,
    /// Account passed in the `rent_payer` slot. Defaults to the zero
    /// address, which matches a [`ChannelBuilder`](crate::common::ChannelBuilder)
    /// blob whose `rent_payer` was never set — so guard tests that target
    /// the status or gate checks pass the rent-payer binding by default.
    pub rent_payer: Pubkey,
    /// Clock slot the run executes at. The reclaim gate requires
    /// `clock.slot > open_slot + OPEN_SLOT_WINDOW`; Mollusk's default clock
    /// sits at slot 0, inside the window of an `open_slot == 0` blob.
    pub clock_slot: u64,
    pub channel_lamports: u64,
    pub rent_payer_lamports: u64,
}

impl ReclaimRun {
    pub fn new(channel_blob: Vec<u8>) -> Self {
        Self {
            channel_blob,
            rent_payer: Pubkey::default(),
            clock_slot: 0,
            channel_lamports: 10_000_000,
            rent_payer_lamports: 1_000_000,
        }
    }

    pub fn run(self) -> ProgramResult {
        self.run_inspect().program_result
    }

    pub fn run_inspect(self) -> InstructionResult {
        let mut mollusk = Mollusk::load_program();
        mollusk.warp_to_slot(self.clock_slot);
        let channel_pubkey = Pubkey::new_unique();

        let ix = build_reclaim_ix(&channel_pubkey, &self.rent_payer);

        let channel_account = Account {
            lamports: self.channel_lamports,
            data: self.channel_blob,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };
        let rent_payer_account = Account {
            lamports: self.rent_payer_lamports,
            ..Default::default()
        };

        mollusk.process_instruction(
            &ix,
            &[
                (channel_pubkey, channel_account),
                (self.rent_payer, rent_payer_account),
            ],
        )
    }
}
