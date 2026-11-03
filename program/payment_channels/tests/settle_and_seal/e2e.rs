//! End-to-end validation of `settleAndSeal` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::{SettleAndSeal, SettleAndSealInstructionArgs};
use payment_channels_client::types::SettleAndSealArgs;
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::{Instruction, error::InstructionError};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{
    ChannelBuilder, INSTRUCTIONS_SYSVAR, PROGRAM_ID, ProgramLoader, expect_custom_err,
    expect_instruction_err, read_channel, set_clock,
    voucher::{build_ed25519_ix, build_metered_pair, voucher, voucher_payload},
};

#[allow(clippy::too_many_arguments)]
fn seed_channel(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    status: ChannelStatus,
    deposit: u64,
    settled: u64,
    closure_started_at: i64,
    grace_period: u32,
    payee: &Pubkey,
    authorized_signer: &Pubkey,
) {
    let data = ChannelBuilder::new()
        .status(status)
        .deposit(deposit)
        .settled(settled)
        .closure_started_at(closure_started_at)
        .grace_period(grace_period)
        .payee(*payee)
        .authorized_signer(*authorized_signer)
        .build();
    svm.set_account(
        *channel,
        Account {
            lamports: 10_000_000,
            data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
}

fn build_saf_ix(channel: &Pubkey, args: SettleAndSealArgs, payee: &Pubkey) -> Instruction {
    SettleAndSeal {
        payee: *payee,
        channel: *channel,
        instructions_sysvar: INSTRUCTIONS_SYSVAR,
    }
    .instruction(SettleAndSealInstructionArgs {
        settle_and_seal_args: args,
    })
}

// ─── happy paths ────────────────────────────────────────────────────────────

#[test]
fn open_to_sealed_with_voucher() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Keypair::new();
    let authorized_signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Open,
        1_000_000,
        0,
        0,
        0,
        &payee.pubkey(),
        &authorized_signer.pubkey(),
    );

    let cumulative = 600_000u64;
    let voucher = voucher(channel, cumulative, 0);
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&authorized_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndSealArgs { has_voucher: 1 },
        &payee.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, saf_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer, &payee],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("tx ok");

    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Sealed as u8);
        assert_eq!(ch.settled(), cumulative);
        assert_eq!(ch.closure_started_at(), 0);
    });
}

// ─── error paths ─────────────────────────────────────────────────────────────

#[test]
fn with_voucher_expired_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let expires_at: i64 = 500;
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = expires_at; // now == expires_at → expired
    svm.set_sysvar::<Clock>(&clock);

    let payee = Keypair::new();
    let authorized_signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Open,
        1_000_000,
        0,
        0,
        0,
        &payee.pubkey(),
        &authorized_signer.pubkey(),
    );

    let voucher = voucher(channel, 100_000, expires_at);
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&authorized_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndSealArgs { has_voucher: 1 },
        &payee.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, saf_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer, &payee],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherExpired,
    );
}

#[test]
fn with_voucher_wrong_authorized_signer_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Keypair::new();
    let authorized_signer = Keypair::new();
    let impostor_signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Open,
        1_000_000,
        0,
        0,
        0,
        &payee.pubkey(),
        &authorized_signer.pubkey(),
    );

    let voucher = voucher(channel, 100_000, 0);
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = impostor_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&impostor_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndSealArgs { has_voucher: 1 },
        &payee.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, saf_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer, &payee],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherSignerMismatch,
    );
}

// ─── metered pair (`has_voucher == 2`) ──────────────────────────────────────
//
// The cap and then the claim sit in the two slots immediately before the
// seal; a successful seal advances `settled` to the claim.

const METERED_DEPOSIT: u64 = 1_000_000;
const METERED_SETTLED: u64 = 250_000;
const METERED_CLAIM: u64 = 500_000;
const METERED_NOW: i64 = 1_000;
const METERED_GRACE: u32 = 3_600;

struct MeteredEnv {
    svm: LiteSVM,
    fee_payer: Keypair,
    payee: Keypair,
    client: Keypair,
    operator: Keypair,
    channel: Pubkey,
}

fn metered_env(status: ChannelStatus, closure_started_at: i64) -> MeteredEnv {
    let mut svm = LiteSVM::load_program();
    set_clock(&mut svm, METERED_NOW);
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Keypair::new();
    let client = Keypair::new();
    let operator = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        status,
        METERED_DEPOSIT,
        METERED_SETTLED,
        closure_started_at,
        METERED_GRACE,
        &payee.pubkey(),
        &client.pubkey(),
    );
    MeteredEnv {
        svm,
        fee_payer,
        payee,
        client,
        operator,
        channel,
    }
}

impl MeteredEnv {
    fn pair(&self) -> (Instruction, Instruction) {
        build_metered_pair(
            &self.channel,
            &self.client,
            &self.operator,
            METERED_DEPOSIT,
            METERED_CLAIM,
            0,
        )
    }

    fn saf_ix(&self, has_voucher: u8) -> Instruction {
        build_saf_ix(
            &self.channel,
            SettleAndSealArgs { has_voucher },
            &self.payee.pubkey(),
        )
    }

    fn send(
        &mut self,
        ixs: &[Instruction],
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>
    {
        let tx = Transaction::new_signed_with_payer(
            ixs,
            Some(&self.fee_payer.pubkey()),
            &[&self.fee_payer, &self.payee],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx)
    }

    fn assert_untouched(&self, status: ChannelStatus) {
        read_channel(&self.svm, &self.channel, |ch| {
            assert_eq!(ch.status, status as u8);
            assert_eq!(ch.settled(), METERED_SETTLED);
        });
    }
}

#[test]
fn open_to_sealed_with_metered_pair() {
    let mut env = metered_env(ChannelStatus::Open, 0);
    let (cap, claim) = env.pair();
    let saf = env.saf_ix(2);
    env.send(&[cap, claim, saf]).expect("tx ok");

    read_channel(&env.svm, &env.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Sealed as u8);
        assert_eq!(ch.settled(), METERED_CLAIM);
        assert_eq!(ch.closure_started_at(), 0);
    });
}

#[test]
fn closing_mid_grace_to_sealed_with_metered_pair() {
    let mut env = metered_env(ChannelStatus::Closing, METERED_NOW - 100);
    let (cap, claim) = env.pair();
    let saf = env.saf_ix(2);
    env.send(&[cap, claim, saf]).expect("tx ok");

    read_channel(&env.svm, &env.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Sealed as u8);
        assert_eq!(ch.settled(), METERED_CLAIM);
        assert_eq!(ch.closure_started_at(), 0);
    });
}

#[test]
fn closing_after_grace_with_metered_pair_rejects() {
    let closure_started_at = METERED_NOW - METERED_GRACE as i64;
    let mut env = metered_env(ChannelStatus::Closing, closure_started_at);
    let (cap, claim) = env.pair();
    let saf = env.saf_ix(2);
    expect_custom_err(
        env.send(&[cap, claim, saf]),
        PaymentChannelsError::InvalidChannelStatus,
    );
    env.assert_untouched(ChannelStatus::Closing);
}

/// A v1 voucher is never a metered pair: the lone 50-byte precompile leaves
/// `current - 2` empty.
#[test]
fn metered_with_v1_voucher_rejects() {
    let mut env = metered_env(ChannelStatus::Open, 0);
    let payload = voucher_payload(&voucher(env.channel, 500_000, 0));
    let signature: [u8; 64] = env.client.sign_message(&payload).into();
    let v1 = build_ed25519_ix(&env.client.pubkey().to_bytes(), &signature, &payload);
    let saf = env.saf_ix(2);
    expect_custom_err(
        env.send(&[v1, saf]),
        PaymentChannelsError::MissingSecondEd25519Verification,
    );
    env.assert_untouched(ChannelStatus::Open);
}

/// `has_voucher == 1` takes the audited v1 path, which rejects the claim at
/// `current - 1` by its `0x56 0x04` magic.
#[test]
fn metered_pair_with_has_voucher_1_rejects() {
    let mut env = metered_env(ChannelStatus::Open, 0);
    let (cap, claim) = env.pair();
    let saf = env.saf_ix(1);
    expect_custom_err(
        env.send(&[cap, claim, saf]),
        PaymentChannelsError::VoucherBadMagic,
    );
    env.assert_untouched(ChannelStatus::Open);
}

/// Only `0`, `1` and `2` are valid tags: anything else fails before any
/// voucher is read, even with a valid v1 voucher in place.
fn unknown_has_voucher_rejects(has_voucher: u8) {
    let mut env = metered_env(ChannelStatus::Open, 0);
    let payload = voucher_payload(&voucher(env.channel, 500_000, 0));
    let signature: [u8; 64] = env.client.sign_message(&payload).into();
    let v1 = build_ed25519_ix(&env.client.pubkey().to_bytes(), &signature, &payload);
    let saf = env.saf_ix(has_voucher);
    expect_instruction_err(
        env.send(&[v1, saf]),
        InstructionError::InvalidInstructionData,
    );
    env.assert_untouched(ChannelStatus::Open);
}

#[test]
fn has_voucher_3_rejects() {
    unknown_has_voucher_rejects(3);
}

#[test]
fn has_voucher_255_rejects() {
    unknown_has_voucher_rejects(u8::MAX);
}
