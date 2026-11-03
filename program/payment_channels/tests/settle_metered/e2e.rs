//! End-to-end checks that `settle_metered` requires one immediate cap precompile
//! followed by one immediate claim precompile, and advances `settled`
//! to the claim on an `OPEN` channel.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::instructions::settle_metered::DISCRIMINATOR;
use payment_channels::{
    CAP_VOUCHER_PAYLOAD_SIZE, CLAIM_VOUCHER_PAYLOAD_SIZE, PaymentChannelsError,
};
use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

use crate::common::{
    ChannelBuilder, INSTRUCTIONS_SYSVAR, PROGRAM_ID, ProgramLoader, expect_custom_err,
    read_channel, set_clock,
    voucher::{
        build_metered_pair, cap_voucher_payload, claim_voucher_payload, signed_cap_ix,
        signed_claim_ix, signed_ed25519_ix, voucher, voucher_payload,
    },
};
use payment_channels::state::ChannelStatus;

const DEPOSIT: u64 = 2_000_000;
const SETTLED: u64 = 250_000;
const CLAIM: u64 = 500_000;
const NOW: i64 = 1_000;
const INSTRUCTION_INDEX_AT: [usize; 3] = [4, 8, 14];

struct Env {
    svm: LiteSVM,
    fee_payer: Keypair,
    client: Keypair,
    operator: Keypair,
    channel: Pubkey,
    settled: u64,
    cap_ix: Instruction,
    claim_ix: Instruction,
}

fn setup() -> Env {
    setup_with_status(ChannelStatus::Open)
}

fn setup_with_status(status: ChannelStatus) -> Env {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let client = Keypair::new();
    let operator = Keypair::new();
    let channel = Pubkey::new_unique();
    let settled = SETTLED;
    let data = ChannelBuilder::new()
        .status(status)
        .deposit(DEPOSIT)
        .settled(settled)
        .authorized_signer(client.pubkey())
        .build();
    svm.set_account(
        channel,
        Account {
            lamports: 10_000_000,
            data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");

    let (cap_ix, claim_ix) = build_metered_pair(&channel, &client, &operator, DEPOSIT, CLAIM, 0);

    Env {
        svm,
        fee_payer,
        client,
        operator,
        channel,
        settled,
        cap_ix,
        claim_ix,
    }
}

fn settle_metered_ix(channel: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &[DISCRIMINATOR],
        vec![
            AccountMeta::new(*channel, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR, false),
        ],
    )
}

fn compute_budget() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(200_000)
}

fn send(
    env: &mut Env,
    ixs: &[Instruction],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&env.fee_payer.pubkey()),
        &[&env.fee_payer],
        env.svm.latest_blockhash(),
    );
    env.svm.send_transaction(tx)
}

fn reject(env: &mut Env, ixs: &[Instruction], expected: PaymentChannelsError) {
    expect_custom_err(send(env, ixs), expected);
    assert_settled_unchanged(env);
}

fn assert_settled_unchanged(env: &Env) {
    assert_settled(env, env.settled);
}

fn assert_settled(env: &Env, expected: u64) {
    let settled = read_channel(&env.svm, &env.channel, |ch| ch.settled());
    assert_eq!(settled, expected);
}

fn assert_precompile_failure_at(env: &mut Env, ixs: &[Instruction], index: u8) {
    let failed = send(env, ixs).expect_err("tx should fail");
    match failed.err {
        TransactionError::InstructionError(ix_index, _) => assert_eq!(ix_index, index),
        other => panic!("expected precompile failure at ix {index}, got {other:?}"),
    }
    assert_settled_unchanged(env);
}

fn prepared(env: &Env) -> (Instruction, Instruction, Instruction) {
    (
        env.cap_ix.clone(),
        env.claim_ix.clone(),
        settle_metered_ix(&env.channel),
    )
}

#[test]
fn compute_budget_before_the_pair_is_accepted() {
    let mut env = setup();
    let (cap, claim, settle) = prepared(&env);
    send(&mut env, &[compute_budget(), cap, claim, settle]).expect("tx ok");
    assert_settled(&env, CLAIM);
}

#[test]
fn claims_advance_under_one_cap_then_under_a_raised_cap() {
    let mut env = setup();
    let settle = settle_metered_ix(&env.channel);
    let pair = |env: &Env, cap, claim| {
        build_metered_pair(&env.channel, &env.client, &env.operator, cap, claim, 0)
    };

    let (cap, claim) = pair(&env, 1_000_000, 500_000);
    send(&mut env, &[cap, claim, settle.clone()]).expect("first claim");
    assert_settled(&env, 500_000);

    let (cap, claim) = pair(&env, 1_000_000, 800_000);
    send(&mut env, &[cap, claim, settle.clone()]).expect("second claim under the same cap");
    assert_settled(&env, 800_000);

    let (cap, claim) = pair(&env, 1_000_000, 1_000_000);
    send(&mut env, &[cap, claim, settle.clone()]).expect("claim equal to the cap");
    assert_settled(&env, 1_000_000);

    let (cap, claim) = pair(&env, 1_000_000, 1_200_000);
    expect_custom_err(
        send(&mut env, &[cap, claim, settle.clone()]),
        PaymentChannelsError::ClaimExceedsCap,
    );
    assert_settled(&env, 1_000_000);

    let (cap, claim) = pair(&env, 1_500_000, 1_200_000);
    send(&mut env, &[cap, claim, settle]).expect("claim under the raised cap");
    assert_settled(&env, 1_200_000);
}

fn rejects_non_open_status(status: ChannelStatus) {
    let mut env = setup_with_status(status);
    let (cap, claim, settle) = prepared(&env);
    reject(
        &mut env,
        &[cap, claim, settle],
        PaymentChannelsError::InvalidChannelStatus,
    );
}

#[test]
fn closing_channel_rejects() {
    rejects_non_open_status(ChannelStatus::Closing);
}

#[test]
fn sealed_channel_rejects() {
    rejects_non_open_status(ChannelStatus::Sealed);
}

#[test]
fn distributed_channel_rejects() {
    rejects_non_open_status(ChannelStatus::Distributed);
}

#[test]
fn missing_preceding_precompile_rejects() {
    let mut env = setup();
    let settle = settle_metered_ix(&env.channel);
    reject(
        &mut env,
        &[settle],
        PaymentChannelsError::MissingSecondEd25519Verification,
    );
}

#[test]
fn swapped_precompile_order_rejects() {
    let mut env = setup();
    let (cap, claim, settle) = prepared(&env);
    reject(
        &mut env,
        &[claim, cap, settle],
        PaymentChannelsError::VoucherBadMagic,
    );
}

#[test]
fn non_ed25519_predecessor_rejects() {
    let mut env = setup();
    let (cap, _, settle) = prepared(&env);
    reject(
        &mut env,
        &[cap, compute_budget(), settle],
        PaymentChannelsError::MissingEd25519Verification,
    );
}

#[test]
fn earlier_pair_does_not_satisfy_the_immediate_slots() {
    let mut env = setup();
    let (cap, claim, settle) = prepared(&env);
    let extra_claim = claim.clone();
    reject(
        &mut env,
        &[cap, claim, extra_claim, settle],
        PaymentChannelsError::VoucherBadMagic,
    );
}

#[test]
fn malformed_precompile_rejects() {
    let mut env = setup();
    let (mut cap, claim, settle) = prepared(&env);
    cap.data.push(0);
    reject(
        &mut env,
        &[cap, claim, settle],
        PaymentChannelsError::MalformedEd25519Instruction,
    );
}

/// The message size picks the voucher kind before any message byte is read:
/// a claim-sized message carrying the cap magic is a bad claim, not a
/// truncated cap.
#[test]
fn cap_magic_on_claim_sized_message_rejects() {
    metered_rejects(
        |env| {
            let mut payload = claim_voucher_payload(&env.channel, CLAIM, 0);
            payload[1] = 0x03;
            (
                good_cap(env, DEPOSIT),
                signed_ed25519_ix(&env.operator, &payload),
            )
        },
        PaymentChannelsError::VoucherBadMagic,
    );
}

#[test]
fn lone_cap_rejects() {
    let mut env = setup();
    let (cap, _, settle) = prepared(&env);
    reject(
        &mut env,
        &[cap, settle],
        PaymentChannelsError::MissingSecondEd25519Verification,
    );
}

#[test]
fn lone_claim_rejects() {
    let mut env = setup();
    let (_, claim, settle) = prepared(&env);
    reject(
        &mut env,
        &[claim, settle],
        PaymentChannelsError::MissingSecondEd25519Verification,
    );
}

fn resized_ix(signer: &Keypair, payload: &[u8], len: usize) -> Instruction {
    let mut message = payload.to_vec();
    message.resize(len, 0);
    signed_ed25519_ix(signer, &message)
}

#[test]
fn wrong_cap_message_size_rejects() {
    for len in [CAP_VOUCHER_PAYLOAD_SIZE - 1, CAP_VOUCHER_PAYLOAD_SIZE + 1] {
        let mut env = setup();
        let (_, claim, settle) = prepared(&env);
        let payload = cap_voucher_payload(&env.channel, DEPOSIT, 0, &env.operator.pubkey());
        let cap = resized_ix(&env.client, &payload, len);
        reject(
            &mut env,
            &[cap, claim, settle],
            PaymentChannelsError::MalformedEd25519Instruction,
        );
    }
}

#[test]
fn wrong_claim_message_size_rejects() {
    for len in [
        CLAIM_VOUCHER_PAYLOAD_SIZE - 1,
        CLAIM_VOUCHER_PAYLOAD_SIZE + 1,
    ] {
        let mut env = setup();
        let (cap, _, settle) = prepared(&env);
        let payload = claim_voucher_payload(&env.channel, CLAIM, 0);
        let claim = resized_ix(&env.operator, &payload, len);
        reject(
            &mut env,
            &[cap, claim, settle],
            PaymentChannelsError::MalformedEd25519Instruction,
        );
    }
}

#[test]
fn claim_rider_byte_rejects() {
    let mut env = setup();
    let (cap, mut claim, settle) = prepared(&env);
    claim.data.push(0);
    reject(
        &mut env,
        &[cap, claim, settle],
        PaymentChannelsError::MalformedEd25519Instruction,
    );
}

fn redirected(ix: &Instruction, at: usize) -> Instruction {
    let mut ix = ix.clone();
    ix.data[at..at + 2].copy_from_slice(&0u16.to_le_bytes());
    ix
}

#[test]
fn cap_cross_instruction_indexes_reject() {
    for at in INSTRUCTION_INDEX_AT {
        let mut env = setup();
        let (cap, claim, settle) = prepared(&env);
        let redirected_cap = redirected(&cap, at);
        reject(
            &mut env,
            &[cap, redirected_cap, claim, settle],
            PaymentChannelsError::MalformedEd25519Instruction,
        );
    }
}

#[test]
fn claim_cross_instruction_indexes_reject() {
    for at in INSTRUCTION_INDEX_AT {
        let mut env = setup();
        let (cap, claim, settle) = prepared(&env);
        let redirected_claim = redirected(&claim, at);
        reject(
            &mut env,
            &[claim, cap, redirected_claim, settle],
            PaymentChannelsError::MalformedEd25519Instruction,
        );
    }
}

#[test]
fn nonzero_padding_rejects() {
    for slot in 0..2 {
        let mut env = setup();
        let (cap, claim, settle) = prepared(&env);
        let mut pair = [cap, claim];
        pair[slot].data[1] = 1;
        let [cap, claim] = pair;
        reject(
            &mut env,
            &[cap, claim, settle],
            PaymentChannelsError::MalformedEd25519Instruction,
        );
    }
}

#[test]
fn invalid_signature_fails_in_the_precompile() {
    let mut env = setup();
    let (mut cap, claim, settle) = prepared(&env);
    let signature_at = payment_channels::ed25519::SIGNATURE_OFFSET;
    cap.data[signature_at..signature_at + 64].fill(0);
    assert_precompile_failure_at(&mut env, &[cap, claim, settle], 0);
}

// ─── rejection matrix ───────────────────────────────────────────────────────

/// Sends `[first, second, settle_metered]` on an OPEN channel at [`NOW`] and
/// expects `expected` with `settled` untouched.
fn metered_rejects(
    build: impl FnOnce(&Env) -> (Instruction, Instruction),
    expected: PaymentChannelsError,
) {
    let mut env = setup();
    set_clock(&mut env.svm, NOW);
    let (first, second) = build(&env);
    let settle = settle_metered_ix(&env.channel);
    reject(&mut env, &[first, second, settle], expected);
}

fn good_cap(env: &Env, cap_cumulative: u64) -> Instruction {
    signed_cap_ix(
        &env.client,
        &env.channel,
        cap_cumulative,
        0,
        &env.operator.pubkey(),
    )
}

fn good_claim(env: &Env, claim_cumulative: u64) -> Instruction {
    signed_claim_ix(&env.operator, &env.channel, claim_cumulative, 0)
}

fn v1_voucher_ix(env: &Env, signer: &Keypair) -> Instruction {
    let payload = voucher_payload(&voucher(env.channel, CLAIM, 0));
    signed_ed25519_ix(signer, &payload)
}

#[test]
fn v1_voucher_in_cap_slot_rejects() {
    metered_rejects(
        |env| (v1_voucher_ix(env, &env.client), good_claim(env, CLAIM)),
        PaymentChannelsError::VoucherBadMagic,
    );
}

#[test]
fn v1_voucher_in_claim_slot_rejects() {
    metered_rejects(
        |env| (good_cap(env, DEPOSIT), v1_voucher_ix(env, &env.operator)),
        PaymentChannelsError::VoucherBadMagic,
    );
}

/// The pair must be one cap and one claim; a second cap can't stand in for
/// the claim, even when the client names itself as operator.
#[test]
fn two_caps_rejects() {
    metered_rejects(
        |env| (good_cap(env, DEPOSIT), good_cap(env, DEPOSIT)),
        PaymentChannelsError::VoucherBadMagic,
    );
}

#[test]
fn two_self_operated_caps_rejects() {
    metered_rejects(
        |env| {
            let cap = || signed_cap_ix(&env.client, &env.channel, CLAIM, 0, &env.client.pubkey());
            (cap(), cap())
        },
        PaymentChannelsError::VoucherBadMagic,
    );
}

#[test]
fn cap_not_signed_by_authorized_signer_rejects() {
    metered_rejects(
        |env| {
            let cap = signed_cap_ix(
                &Keypair::new(),
                &env.channel,
                DEPOSIT,
                0,
                &env.operator.pubkey(),
            );
            (cap, good_claim(env, CLAIM))
        },
        PaymentChannelsError::VoucherSignerMismatch,
    );
}

#[test]
fn claim_not_signed_by_cap_operator_rejects() {
    metered_rejects(
        |env| {
            let claim = signed_claim_ix(&Keypair::new(), &env.channel, CLAIM, 0);
            (good_cap(env, DEPOSIT), claim)
        },
        PaymentChannelsError::VoucherOperatorMismatch,
    );
}

#[test]
fn expired_cap_rejects() {
    metered_rejects(
        |env| {
            let cap = signed_cap_ix(
                &env.client,
                &env.channel,
                DEPOSIT,
                NOW,
                &env.operator.pubkey(),
            );
            (cap, good_claim(env, CLAIM))
        },
        PaymentChannelsError::VoucherExpired,
    );
}

#[test]
fn expired_claim_rejects() {
    metered_rejects(
        |env| {
            let claim = signed_claim_ix(&env.operator, &env.channel, CLAIM, NOW);
            (good_cap(env, DEPOSIT), claim)
        },
        PaymentChannelsError::VoucherExpired,
    );
}

#[test]
fn unexpired_pair_is_accepted() {
    let mut env = setup();
    set_clock(&mut env.svm, NOW);
    let cap = signed_cap_ix(
        &env.client,
        &env.channel,
        DEPOSIT,
        NOW + 1,
        &env.operator.pubkey(),
    );
    let claim = signed_claim_ix(&env.operator, &env.channel, CLAIM, NOW + 1);
    let settle = settle_metered_ix(&env.channel);
    send(&mut env, &[cap, claim, settle]).expect("tx ok");
    assert_settled(&env, CLAIM);
}

#[test]
fn cap_for_other_channel_rejects() {
    metered_rejects(
        |env| {
            let cap = signed_cap_ix(
                &env.client,
                &Pubkey::new_unique(),
                DEPOSIT,
                0,
                &env.operator.pubkey(),
            );
            (cap, good_claim(env, CLAIM))
        },
        PaymentChannelsError::VoucherChannelMismatch,
    );
}

#[test]
fn claim_for_other_channel_rejects() {
    metered_rejects(
        |env| {
            let claim = signed_claim_ix(&env.operator, &Pubkey::new_unique(), CLAIM, 0);
            (good_cap(env, DEPOSIT), claim)
        },
        PaymentChannelsError::VoucherChannelMismatch,
    );
}

#[test]
fn cap_above_deposit_rejects() {
    metered_rejects(
        |env| (good_cap(env, DEPOSIT + 1), good_claim(env, CLAIM)),
        PaymentChannelsError::VoucherOverDeposit,
    );
}

#[test]
fn claim_equal_to_settled_rejects() {
    metered_rejects(
        |env| (good_cap(env, DEPOSIT), good_claim(env, SETTLED)),
        PaymentChannelsError::VoucherWatermarkNotMonotonic,
    );
}

#[test]
fn claim_below_settled_rejects() {
    metered_rejects(
        |env| (good_cap(env, DEPOSIT), good_claim(env, SETTLED - 1)),
        PaymentChannelsError::VoucherWatermarkNotMonotonic,
    );
}
