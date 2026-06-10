//! End-to-end validation of `settle` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use payment_channels::ed25519;
use payment_channels_client::instructions::{Settle, SettleInstructionArgs};
use payment_channels_client::types::{SettleArgs, VoucherArgs};
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use solana_compute_budget_interface::ComputeBudgetInstruction;

use crate::common::{
    ChannelBuilder, INSTRUCTIONS_SYSVAR, PROGRAM_ID, ProgramLoader, expect_custom_err,
    read_channel,
    voucher::{TEST_CHAIN_ID, build_ed25519_ix, voucher_payload},
};
use payment_channels::state::ChannelStatus;

/// Seed a `Channel` PDA owned by the program with the fields `settle` reads.
fn seed_channel(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    status: u8,
    deposit: u64,
    settled: u64,
    authorized_signer: &Pubkey,
) {
    let data = ChannelBuilder::new()
        .status(channel_status_from_u8(status))
        .deposit(deposit)
        .settled(settled)
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

fn channel_status_from_u8(s: u8) -> ChannelStatus {
    ChannelStatus::try_from(s).expect("valid status byte")
}

fn build_settle_ix(channel: &Pubkey, voucher: VoucherArgs) -> Instruction {
    Settle {
        channel: *channel,
        instructions_sysvar: INSTRUCTIONS_SYSVAR,
    }
    .instruction(SettleInstructionArgs {
        settle_args: SettleArgs { voucher },
    })
}

fn read_settled(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    read_channel(svm, channel, |ch| ch.settled())
}

#[test]
fn settle_advances_watermark_on_valid_voucher() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let cumulative = 500_000u64;
    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: cumulative,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("tx ok");

    assert_eq!(read_settled(&svm, &channel), cumulative);
}

#[test]
fn settle_batches_two_paired_ix_advance_watermark() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let voucher_1 = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 300_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let voucher_2 = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };

    let payload_1 = voucher_payload(&voucher_1);
    let payload_2 = voucher_payload(&voucher_2);
    let signature_1: [u8; 64] = signer.sign_message(&payload_1).into();
    let signature_2: [u8; 64] = signer.sign_message(&payload_2).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix_1 = build_ed25519_ix(&pubkey, &signature_1, &payload_1);
    let ed25519_ix_2 = build_ed25519_ix(&pubkey, &signature_2, &payload_2);
    let settle_ix_1 = build_settle_ix(&channel, voucher_1);
    let settle_ix_2 = build_settle_ix(&channel, voucher_2);

    // Batch layout `[ed25519_1, settle_1, ed25519_2, settle_2]`: each
    // `settle` reads its paired ed25519 ix at `current - 1`. Positional
    // pairing — not "any ed25519 in the tx". Second settle also exercises
    // monotonic progression from the in-tx-updated watermark (300_000 →
    // 500_000), not the seeded 0.
    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix_1, settle_ix_1, ed25519_ix_2, settle_ix_2],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("tx ok");

    assert_eq!(read_settled(&svm, &channel), 500_000);
}

#[test]
fn settle_without_preceding_ed25519_ix_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let settle_ix = build_settle_ix(
        &channel,
        VoucherArgs {
            channel_id: channel,
            cumulative_amount: 500_000,
            expires_at: 0,
            chain_id: TEST_CHAIN_ID,
        },
    );

    let tx = Transaction::new_signed_with_payer(
        &[settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::MissingEd25519Verification,
    );
}

#[test]
fn settle_after_expiry_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    // Pin `now >= expires_at` by warping the Clock sysvar to the
    // voucher's TTL. `verify_voucher` rejects on `>=`, so equality
    // is the tight boundary of "expiry has been reached".
    let expires_at: i64 = 1_700_000_000;
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = expires_at;
    svm.set_sysvar::<Clock>(&clock);

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherExpired,
    );
}

#[test]
fn settle_voucher_channel_mismatch_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel_a = Pubkey::new_unique();
    let channel_b = Pubkey::new_unique();
    seed_channel(&mut svm, &channel_a, 0, 1_000_000, 0, &signer.pubkey());

    let voucher = VoucherArgs {
        channel_id: channel_b,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel_a, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherChannelMismatch,
    );
}

#[test]
fn settle_voucher_over_deposit_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 500_000, 0, &signer.pubkey());

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_001,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherOverDeposit,
    );
}

#[test]
fn settle_voucher_foreign_chain_id_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    // Correctly signed, correct channel, within deposit — but bound to another
    // cluster's chain id. The ed25519 precompile passes; the program must reject
    // the cross-cluster replay at the CHAIN_ID check.
    let foreign_chain = Pubkey::new_unique();
    assert_ne!(foreign_chain, TEST_CHAIN_ID);
    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: foreign_chain,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherChainMismatch,
    );
}

#[test]
fn settle_voucher_not_monotonic_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 500_000, &signer.pubkey());

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherWatermarkNotMonotonic,
    );
}

#[test]
fn settle_voucher_message_mismatch_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    // Sign one payload but submit a different `VoucherArgs`. Both cumulative
    // values pass cap/monotonicity, so only the message check can fire.
    let voucher_signed = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 100_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let voucher_submitted = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 200_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload_signed = voucher_payload(&voucher_signed);
    let signature: [u8; 64] = signer.sign_message(&payload_signed).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload_signed);
    let settle_ix = build_settle_ix(&channel, voucher_submitted);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherMessageMismatch,
    );
}

#[test]
fn settle_voucher_signer_mismatch_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let authorized = Keypair::new();
    let impostor = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &authorized.pubkey());

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = impostor.sign_message(&payload).into();
    let pubkey = impostor.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherSignerMismatch,
    );
}

#[test]
fn settle_malformed_ed25519_ix_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    // Flip the padding byte: the Solana Ed25519 precompile does not
    // inspect `data[1]`, so the ix clears precompile verification; the
    // program's `parse` then rejects on the `padding == 0` guard.
    let mut ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    ed25519_ix.data[1] = 1;
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::MalformedEd25519Instruction,
    );
}

#[test]
fn settle_preceding_compute_budget_ix_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    // Preceding ix resolves cleanly, but its program id is not the Ed25519
    // precompile — exercises the program-id branch of
    // `MissingEd25519Verification`.
    let preceding_ix = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[preceding_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::MissingEd25519Verification,
    );
}

#[test]
fn settle_with_invalid_signature_rejects_before_settle_runs() {
    // Canonical precompile ix layout (correct pubkey, correct message,
    // canonical offsets) paired with a zeroed signature: cryptographically
    // invalid for any (pubkey, message). The native Ed25519SigVerify
    // precompile must reject at ix index 0 — our settle (ix index 1)
    // never runs. Distinct from `settle_malformed_ed25519_ix_rejects`,
    // which tampers a field the precompile ignores and only trips our
    // program's `parse` guard.
    use solana_transaction_error::TransactionError;

    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 500_000,
        expires_at: 0,
        chain_id: TEST_CHAIN_ID,
    };
    let payload = voucher_payload(&voucher);
    let pubkey = signer.pubkey().to_bytes();
    let forged_signature = [0u8; ed25519::SIGNATURE_SERIALIZED_SIZE];

    let ed25519_ix = build_ed25519_ix(&pubkey, &forged_signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    let failed = svm.send_transaction(tx).expect_err("tx should fail");

    // Pin the failure at instruction index 0 (precompile). A failure at
    // index 1 would mean our program ran — exactly what this test rules
    // out. The ix is structurally valid, so the only thing that can fail
    // at index 0 is signature verification.
    match failed.err {
        TransactionError::InstructionError(0, _) => {}
        other => panic!("expected precompile failure at ix 0, got {other:?}"),
    }

    // Cross-check: settle never wrote the watermark.
    assert_eq!(read_settled(&svm, &channel), 0);
}
