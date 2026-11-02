//! Mollusk-driven validation tests for `distribute`. These exercise the
//! instruction's pre-CPI guards (status, payer authorization, mint binding)
//! without spinning up a full LiteSVM token environment — the heavyweight
//! token-flow scenarios live in [`super::e2e`].

use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use super::{DistributeRun, Split};
use crate::common::token_2022::mint_policy_cases;
use crate::common::{ChannelBuilder, TOKEN_2022};

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
            PaymentChannelsError::InvalidChannelMint as u32
        )),
    );
}

#[test]
fn legacy_tombstone_account_rejects() {
    // 1-byte accounts carrying the reserved `ClosedChannel` discriminator
    // (= 2) are leftovers of the pre-launch deployment's tombstone close;
    // the program no longer produces them — a fully closed channel is
    // deallocated entirely. `Channel::load_mut` length-gates inside
    // `unsafe load_mut::<Channel>` before any discriminator/version/status
    // logic runs, so the program rejects with `InvalidAccountData` for any
    // buffer whose length is not exactly `Channel::LEN`.
    let payer = Pubkey::new_unique();
    let splits = one_split();
    assert_eq!(
        DistributeRun::new(vec![2u8], payer, &splits).run(),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}

/// Mint policy runs after the status and identity checks and before any CPI.
#[test]
fn token_2022_mint_policy_gate_runs_before_any_cpi() {
    for (label, mint_account, expected) in
        mint_policy_cases(PaymentChannelsError::ChannelAccountMismatch)
    {
        let payer = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let splits = one_split();
        let run = DistributeRun {
            mint,
            token_program: TOKEN_2022,
            mint_account: Some(mint_account),
            ..DistributeRun::new(
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .deposit(DEPOSIT)
                    .payer(payer)
                    .rent_payer(payer)
                    .mint(mint)
                    .build(),
                payer,
                &splits,
            )
        };
        assert_eq!(
            run.run(),
            ProgramResult::Failure(ProgramError::Custom(expected as u32)),
            "{label}"
        );
    }
}
