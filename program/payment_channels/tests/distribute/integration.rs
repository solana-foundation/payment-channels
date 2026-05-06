//! Mollusk-driven validation tests for `distribute`. These exercise the
//! instruction's pre-CPI guards (status, payer authorization, mint binding)
//! without spinning up a full LiteSVM token environment — the heavyweight
//! token-flow scenarios live in [`super::e2e`].

use mollusk_svm::result::ProgramResult;
use payment_channels_core::PaymentChannelsError;
use payment_channels_core::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use super::{DistributeRun, Split};
use crate::common::ChannelBuilder;

const DEPOSIT: u64 = 1_000_000;

fn one_split() -> Vec<Split> {
    vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5_000,
    }]
}

#[test]
fn closing_status_rejects() {
    let payer = Pubkey::new_unique();
    let splits = one_split();
    assert_eq!(
        DistributeRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .deposit(DEPOSIT)
                .payer(payer)
                .build(),
            payer,
            &splits,
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelNotDistributable as u32
        )),
    );
}

#[test]
fn wrong_mint_rejects() {
    // `distribute` binds the `mint` account to `channel.mint`. A random
    // `mint` against a `ChannelBuilder` that committed `Pubkey::default()`
    // exercises that guard.
    let payer = Pubkey::new_unique();
    let splits = one_split();
    assert_eq!(
        DistributeRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(payer)
                .build(),
            payer,
            &splits,
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MintAccountMismatch as u32
        )),
    );
}

#[test]
fn tombstoned_channel_rejects() {
    // After FINALIZED `distribute` tombstones the PDA, the channel data
    // shrinks to a 1-byte `ClosedChannel` payload (discriminator = 2).
    // `Channel::load_mut` length-gates inside `unsafe load_mut::<Channel>`
    // before any discriminator/version/status logic runs, so the program
    // rejects with `InvalidAccountData` for any buffer whose length is
    // not exactly `Channel::LEN` (216).
    let payer = Pubkey::new_unique();
    let splits = one_split();
    assert_eq!(
        DistributeRun::new(vec![2u8], payer, &splits).run(),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}
