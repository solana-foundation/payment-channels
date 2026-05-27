//! Canonical happy-path scenarios per instruction. Each `#[test]` builds
//! the focal tx and calls [`super::record`] with a stable, sortable label.
//!
//! Label convention: `instruction[k=v,k=v,...]`, with the numeric `n=` field
//! zero-padded to two digits so lexicographic sort in the report mirrors a
//! natural parameter sweep (`n=01 < n=04 < n=16 < n=32`).

#![allow(clippy::result_large_err)]

use payment_channels_client::instructions::{
    Distribute, DistributeInstructionArgs, Finalize, RequestClose, SettleAndFinalize,
    SettleAndFinalizeInstructionArgs, TopUp, TopUpInstructionArgs, WithdrawPayer,
};
use payment_channels_client::types::{
    DistributeArgs, DistributionEntry, SettleAndFinalizeArgs, VoucherArgs,
};
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{AddressLookupTableAccount, VersionedMessage, v0::Message as MessageV0};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction::versioned::VersionedTransaction;

use litesvm::LiteSVM;

use super::fixtures::{
    self, DEFAULT_DEPOSIT, DEFAULT_SETTLED, Fixture, GRACE_PERIOD, build_settle_pair,
};
use super::record;
use crate::common::{
    INSTRUCTIONS_SYSVAR, ProgramLoader, SPL_TOKEN, TOKEN_2022, compute_budget_ix, mutate_channel,
    set_clock,
    voucher::{build_ed25519_ix, voucher_payload},
};

const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Wrap the focal ixs in `[compute_budget(1.4M), ...]` and sign with the
/// fee payer. Centralized so every scenario pays the same setup cost in
/// the recorded tx.
fn build_focal_tx(
    svm: &LiteSVM,
    fee_payer: &solana_keypair::Keypair,
    extra_signers: &[&solana_keypair::Keypair],
    ixs: &[Instruction],
) -> Transaction {
    let mut full = Vec::with_capacity(ixs.len() + 1);
    full.push(compute_budget_ix(COMPUTE_UNIT_LIMIT));
    full.extend_from_slice(ixs);
    let mut signers: Vec<&solana_keypair::Keypair> = vec![fee_payer];
    signers.extend_from_slice(extra_signers);
    Transaction::new_signed_with_payer(
        &full,
        Some(&fee_payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    )
}

/// Same shape as [`build_focal_tx`] but wraps the focal ixs in a v0
/// transaction that resolves account metas through `alt`. Used by scenarios
/// where the legacy 1232-byte account list overflows (e.g. n=32 distribute).
fn build_focal_v0_tx(
    svm: &LiteSVM,
    fee_payer: &solana_keypair::Keypair,
    extra_signers: &[&solana_keypair::Keypair],
    ixs: &[Instruction],
    alt: &AddressLookupTableAccount,
) -> VersionedTransaction {
    let mut full = Vec::with_capacity(ixs.len() + 1);
    full.push(compute_budget_ix(COMPUTE_UNIT_LIMIT));
    full.extend_from_slice(ixs);
    let msg = MessageV0::try_compile(
        &fee_payer.pubkey(),
        &full,
        std::slice::from_ref(alt),
        svm.latest_blockhash(),
    )
    .expect("compile v0 message");
    let mut signers: Vec<&solana_keypair::Keypair> = vec![fee_payer];
    signers.extend_from_slice(extra_signers);
    VersionedTransaction::try_new(VersionedMessage::V0(msg), &signers).expect("sign v0 tx")
}

// ───────────────────────────────────────────────────────────────────────────
// open — sweep recipients × token program.

fn run_open(num_recipients: usize, token_program: solana_pubkey::Pubkey, label: &str) {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, num_recipients, token_program);
    let ix = fixtures::build_open_ix(&f, DEFAULT_DEPOSIT);
    let tx = build_focal_tx(&svm, &f.payer, &[], &[ix]);
    record(&mut svm, tx, label).expect("open ok");
}

/// Baseline `open` cost on SPL Token: 1-entry distribution_hash commit,
/// full channel-PDA + channel-ATA creation, event self-CPI. Floor of the
/// per-recipient curve.
#[test]
fn open_n01_spl() {
    run_open(1, SPL_TOKEN, "open[n=01,tok=spl]");
}

/// `open` at 4 splits, SPL. Pins the per-recipient hashing slope vs `n=1`.
#[test]
fn open_n04_spl() {
    run_open(4, SPL_TOKEN, "open[n=04,tok=spl]");
}

/// `open` at 16 splits, SPL. Mid-range realistic configuration.
#[test]
fn open_n16_spl() {
    run_open(16, SPL_TOKEN, "open[n=16,tok=spl]");
}

/// `open` at `MAX_DISTRIBUTION_RECIPIENTS` (32), SPL. Caps the
/// per-recipient curve at the protocol limit.
#[test]
fn open_n32_spl() {
    run_open(32, SPL_TOKEN, "open[n=32,tok=spl]");
}

/// `open` at 1 split on Token-2022. Isolates the SPL → Token-2022
/// mint-init / ATA-create cost delta.
#[test]
fn open_n01_t22() {
    run_open(1, TOKEN_2022, "open[n=01,tok=t22]");
}

/// `open` at 16 splits on Token-2022. Per-recipient slope on the heavier
/// token program.
#[test]
fn open_n16_t22() {
    run_open(16, TOKEN_2022, "open[n=16,tok=t22]");
}

/// `open` at `MAX_DISTRIBUTION_RECIPIENTS` (32) on Token-2022. Caps the
/// per-recipient curve at the protocol limit on the heavier token program.
#[test]
fn open_n32_t22() {
    run_open(32, TOKEN_2022, "open[n=32,tok=t22]");
}

// ───────────────────────────────────────────────────────────────────────────
// settle — fresh vs advance against an existing watermark.

/// First settle on an OPEN channel against a zero watermark: ed25519
/// precompile verify + voucher decode + monotonicity / deposit-cap checks
/// + watermark write.
#[test]
fn settle_fresh() {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, 1, SPL_TOKEN);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);
    let (ed_ix, settle_ix) = build_settle_pair(&f, DEFAULT_SETTLED, 0);
    let tx = build_focal_tx(&svm, &f.payer, &[], &[ed_ix, settle_ix]);
    record(&mut svm, tx, "settle[fresh]").expect("settle ok");
}

/// Second settle against a non-zero watermark. Same wire path as
/// `settle_fresh`; sample confirms the "advance from non-zero" branch is
/// flat (no per-watermark cost).
#[test]
fn settle_advance() {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, 1, SPL_TOKEN);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);
    // Pre-advance watermark via a real settle setup tx so the focal tx
    // exercises the "non-zero settled → larger settled" branch.
    fixtures::settle_setup(&mut svm, &f, DEFAULT_SETTLED / 2);
    let (ed_ix, settle_ix) = build_settle_pair(&f, DEFAULT_SETTLED, 0);
    let tx = build_focal_tx(&svm, &f.payer, &[], &[ed_ix, settle_ix]);
    record(&mut svm, tx, "settle[advance]").expect("settle ok");
}

// ───────────────────────────────────────────────────────────────────────────
// top_up — SPL + Token-2022.

fn run_top_up(token_program: solana_pubkey::Pubkey, label: &str) {
    use litesvm_token::MintTo;
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, 1, token_program);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);
    // Mint extra tokens to the payer ATA so top_up has balance to move.
    let top_up_amount = DEFAULT_DEPOSIT / 2;
    MintTo::new(&mut svm, &f.payer, &f.mint, &f.payer_ata, top_up_amount)
        .token_program_id(&token_program)
        .send()
        .unwrap();

    let ix = TopUp {
        payer: f.payer.pubkey(),
        channel: f.channel,
        payer_token_account: f.payer_ata,
        channel_token_account: f.channel_ata,
        mint: f.mint,
        token_program,
    }
    .instruction(TopUpInstructionArgs {
        top_up_args: payment_channels_client::types::TopUpArgs {
            amount: top_up_amount,
        },
    });
    let tx = build_focal_tx(&svm, &f.payer, &[], &[ix]);
    record(&mut svm, tx, label).expect("top_up ok");
}

/// SPL Token `top_up`: payer-signed `transfer_checked` into escrow +
/// in-place `deposit` field bump. No PDA work.
#[test]
fn top_up_spl() {
    run_top_up(SPL_TOKEN, "top_up[tok=spl]");
}

/// Token-2022 `top_up`. T22's `transfer_checked` walks extension headers
/// on every account — pins the SPL → T22 cost delta on the deposit path.
#[test]
fn top_up_t22() {
    run_top_up(TOKEN_2022, "top_up[tok=t22]");
}

// ───────────────────────────────────────────────────────────────────────────
// request_close — payer-signed, no token movement.

/// Cheapest mutator in the program: payer-signed status flip
/// (`OPEN → CLOSING`) + `closure_started_at` stamp. No CPI, no token
/// movement, single-account write — the protocol's CU floor.
#[test]
fn request_close() {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, 1, SPL_TOKEN);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);
    let ix = RequestClose {
        payer: f.payer.pubkey(),
        channel: f.channel,
    }
    .instruction();
    let tx = build_focal_tx(&svm, &f.payer, &[], &[ix]);
    record(&mut svm, tx, "request_close").expect("request_close ok");
}

// ───────────────────────────────────────────────────────────────────────────
// finalize — CLOSING → FINALIZED post-grace. State mutated directly so we
// measure finalize alone (not the open + request_close prelude).

/// Post-grace `CLOSING → FINALIZED` transition: Clock-read against
/// `closure_started_at + grace_period`, status flip, `closure_started_at`
/// cleared. No CPI, permissionless crank.
#[test]
fn finalize() {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, 1, SPL_TOKEN);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);

    let closure_at: i64 = 1_000_000;
    mutate_channel(&mut svm, &f.channel, |ch| {
        ch.status = fixtures::status::CLOSING;
        ch.set_closure_started_at(closure_at);
    });
    set_clock(&mut svm, closure_at + GRACE_PERIOD as i64);

    let ix = Finalize { channel: f.channel }.instruction();
    let tx = build_focal_tx(&svm, &f.payer, &[], &[ix]);
    record(&mut svm, tx, "finalize").expect("finalize ok");
}

// ───────────────────────────────────────────────────────────────────────────
// settle_and_finalize — merchant-signed transition, with or without voucher
// across the OPEN → FINALIZED and CLOSING → FINALIZED entry points.

fn run_settle_and_finalize(from_closing: bool, label: &str) {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, 1, SPL_TOKEN);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);
    if from_closing {
        let closure_at: i64 = 1_000_000;
        mutate_channel(&mut svm, &f.channel, |ch| {
            ch.status = fixtures::status::CLOSING;
            ch.set_closure_started_at(closure_at);
        });
        // Keep `now < closure_at + grace_period` so the CLOSING → FINALIZED
        // mid-grace path is exercised.
        set_clock(&mut svm, closure_at + 10);
    }
    let voucher = VoucherArgs {
        channel_id: f.channel,
        cumulative_amount: DEFAULT_SETTLED,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = f.authorized_signer.sign_message(&payload).into();
    let ed_ix = build_ed25519_ix(
        &f.authorized_signer.pubkey().to_bytes(),
        &signature,
        &payload,
    );
    let saf_ix = SettleAndFinalize {
        merchant: f.payee.pubkey(),
        channel: f.channel,
        instructions_sysvar: INSTRUCTIONS_SYSVAR,
    }
    .instruction(SettleAndFinalizeInstructionArgs {
        settle_and_finalize_args: SettleAndFinalizeArgs {
            voucher,
            has_voucher: 1,
        },
    });
    let tx = build_focal_tx(&svm, &f.payer, &[&f.payee], &[ed_ix, saf_ix]);
    record(&mut svm, tx, label).expect("settle_and_finalize ok");
}

/// Merchant-signed cooperative close from OPEN: ed25519-verified final
/// voucher + watermark commit + `OPEN → FINALIZED`. `closure_started_at`
/// left untouched (was 0).
#[test]
fn settle_and_finalize_from_open() {
    run_settle_and_finalize(false, "settle_and_finalize[from_open]");
}

/// Cooperative close mid-grace from CLOSING. Same wire path as
/// `from_open`, plus the additional `closure_started_at → 0` write that's
/// only triggered when the prior status was CLOSING.
#[test]
fn settle_and_finalize_from_closing() {
    run_settle_and_finalize(true, "settle_and_finalize[from_closing]");
}

// ───────────────────────────────────────────────────────────────────────────
// distribute — sweep recipients × token program × final-status path.

fn run_distribute(
    f: &Fixture,
    svm: &mut LiteSVM,
    accts: &fixtures::DistributeAccounts,
    label: &str,
) {
    let recipients: Vec<DistributionEntry> = f
        .splits
        .iter()
        .map(|(owner, bps)| DistributionEntry {
            recipient: *owner,
            bps: *bps,
        })
        .collect();
    let remaining: Vec<AccountMeta> = accts
        .recipient_atas
        .iter()
        .map(|a| AccountMeta::new(*a, false))
        .collect();
    let ix = Distribute {
        channel: f.channel,
        payer: f.payer.pubkey(),
        channel_token_account: f.channel_ata,
        payer_token_account: f.payer_ata,
        payee_token_account: accts.payee_ata,
        treasury_token_account: accts.treasury_ata,
        mint: f.mint,
        token_program: f.token_program,
    }
    .instruction_with_remaining_accounts(
        DistributeInstructionArgs {
            distribute_args: DistributeArgs { recipients },
        },
        &remaining,
    );
    let tx = build_focal_tx(svm, &f.payer, &[], &[ix]);
    record(svm, tx, label).expect("distribute ok");
}

fn distribute_setup_open(
    num_recipients: usize,
    token_program: solana_pubkey::Pubkey,
) -> (LiteSVM, Fixture, fixtures::DistributeAccounts) {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, num_recipients, token_program);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);
    fixtures::settle_setup(&mut svm, &f, DEFAULT_SETTLED);
    let accts = fixtures::create_distribute_atas(&mut svm, &f);
    (svm, f, accts)
}

fn distribute_setup_finalized(
    num_recipients: usize,
    token_program: solana_pubkey::Pubkey,
) -> (LiteSVM, Fixture, fixtures::DistributeAccounts) {
    let (mut svm, f, accts) = distribute_setup_open(num_recipients, token_program);
    // Mutate to FINALIZED so the focal tx exercises the
    // treasury-sweep + payer-refund + tombstone branch.
    mutate_channel(&mut svm, &f.channel, |ch| {
        ch.status = fixtures::status::FINALIZED
    });
    (svm, f, accts)
}

/// Baseline `distribute` on an OPEN channel, SPL, 1 recipient: preimage
/// hash check + one `transfer_checked` to the recipient + one to the
/// payee for the implicit share. Floor of the recipient-loop curve.
#[test]
fn distribute_n01_spl_open() {
    let (mut svm, f, accts) = distribute_setup_open(1, SPL_TOKEN);
    run_distribute(&f, &mut svm, &accts, "distribute[n=01,tok=spl,open]");
}

/// `distribute` at 4 recipients, OPEN, SPL. Pins the per-recipient
/// `transfer_checked` slope vs `n=1`.
#[test]
fn distribute_n04_spl_open() {
    let (mut svm, f, accts) = distribute_setup_open(4, SPL_TOKEN);
    run_distribute(&f, &mut svm, &accts, "distribute[n=04,tok=spl,open]");
}

/// `distribute` at 16 recipients, OPEN, SPL. High end of the
/// legacy-tx-sized SPL sweep (32 recipients overflows the tx-size limit;
/// see comment below).
#[test]
fn distribute_n16_spl_open() {
    let (mut svm, f, accts) = distribute_setup_open(16, SPL_TOKEN);
    run_distribute(&f, &mut svm, &accts, "distribute[n=16,tok=spl,open]");
}

/// `distribute` at 16 recipients on Token-2022, OPEN. Per-recipient
/// `transfer_checked` cost on the heavier token program (extension
/// scans per account).
#[test]
fn distribute_n16_t22_open() {
    let (mut svm, f, accts) = distribute_setup_open(16, TOKEN_2022);
    run_distribute(&f, &mut svm, &accts, "distribute[n=16,tok=t22,open]");
}

/// `distribute` from FINALIZED at 1 recipient, SPL. Adds the tombstone
/// branch on top of the OPEN baseline: residual sweep to treasury, payer
/// refund of `deposit - settled`, channel-PDA shrink-to-tombstone.
#[test]
fn distribute_n01_spl_fin() {
    let (mut svm, f, accts) = distribute_setup_finalized(1, SPL_TOKEN);
    run_distribute(&f, &mut svm, &accts, "distribute[n=01,tok=spl,fin]");
}

/// `distribute` from FINALIZED at 16 recipients, SPL. Tombstone branch
/// stacked on the high-end recipient-loop cost.
#[test]
fn distribute_n16_spl_fin() {
    let (mut svm, f, accts) = distribute_setup_finalized(16, SPL_TOKEN);
    run_distribute(&f, &mut svm, &accts, "distribute[n=16,tok=spl,fin]");
}

// n=32 (`MAX_DISTRIBUTION_RECIPIENTS`) overflows the 1232-byte legacy tx
// account-list, so the next three scenarios pack the recipient ATAs into an
// ALT and submit a v0 transaction. The on-chain program sees identical
// account metas either way; the v0 wrapping pays a small per-tx CU surcharge
// for ALT resolution but the per-recipient on-chain slope is what's being
// captured here.

fn run_distribute_alt(
    f: &Fixture,
    svm: &mut LiteSVM,
    accts: &fixtures::DistributeAccounts,
    label: &str,
) {
    let recipients: Vec<DistributionEntry> = f
        .splits
        .iter()
        .map(|(owner, bps)| DistributionEntry {
            recipient: *owner,
            bps: *bps,
        })
        .collect();
    let remaining: Vec<AccountMeta> = accts
        .recipient_atas
        .iter()
        .map(|a| AccountMeta::new(*a, false))
        .collect();
    let ix = Distribute {
        channel: f.channel,
        payer: f.payer.pubkey(),
        channel_token_account: f.channel_ata,
        payer_token_account: f.payer_ata,
        payee_token_account: accts.payee_ata,
        treasury_token_account: accts.treasury_ata,
        mint: f.mint,
        token_program: f.token_program,
    }
    .instruction_with_remaining_accounts(
        DistributeInstructionArgs {
            distribute_args: DistributeArgs { recipients },
        },
        &remaining,
    );
    // Only the recipient ATAs are packed into the ALT — the 8 fixed
    // distribute accounts always sit in the message's account_keys table.
    let alt = fixtures::build_address_lookup_table(svm, &f.payer, accts.recipient_atas.clone());
    let tx = build_focal_v0_tx(svm, &f.payer, &[], &[ix], &alt);
    record(svm, tx, label).expect("distribute ok");
}

/// `distribute` at `MAX_DISTRIBUTION_RECIPIENTS` (32) on SPL, OPEN. Submitted
/// via v0 + ALT because the 32 recipient ATAs overflow the legacy tx
/// account-list cap. Caps the per-recipient curve at the protocol limit.
#[test]
fn distribute_n32_spl_open() {
    let (mut svm, f, accts) = distribute_setup_open(32, SPL_TOKEN);
    run_distribute_alt(&f, &mut svm, &accts, "distribute[n=32,tok=spl,open]");
}

/// `distribute` at 32 recipients on Token-2022, OPEN, via ALT. Caps the
/// per-recipient curve on the heavier token program.
#[test]
fn distribute_n32_t22_open() {
    let (mut svm, f, accts) = distribute_setup_open(32, TOKEN_2022);
    run_distribute_alt(&f, &mut svm, &accts, "distribute[n=32,tok=t22,open]");
}

/// `distribute` at 32 recipients on SPL, FINALIZED, via ALT. Tombstone
/// branch stacked on the protocol-max recipient-loop cost.
#[test]
fn distribute_n32_spl_fin() {
    let (mut svm, f, accts) = distribute_setup_finalized(32, SPL_TOKEN);
    run_distribute_alt(&f, &mut svm, &accts, "distribute[n=32,tok=spl,fin]");
}

// ───────────────────────────────────────────────────────────────────────────
// withdraw_payer — FINALIZED-only, payer-signed one-shot refund.

fn run_withdraw_payer(token_program: solana_pubkey::Pubkey, label: &str) {
    let mut svm = LiteSVM::load_program();
    let f = fixtures::prepare_channel(&mut svm, 1, token_program);
    fixtures::open_setup(&mut svm, &f, DEFAULT_DEPOSIT);
    // Skip the request_close + grace + finalize prelude — measure withdraw_payer alone.
    mutate_channel(&mut svm, &f.channel, |ch| {
        ch.status = fixtures::status::FINALIZED;
        ch.set_settled(DEFAULT_SETTLED);
    });
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 1_000_000;
    svm.set_sysvar::<Clock>(&clock);

    let ix = WithdrawPayer {
        payer: f.payer.pubkey(),
        channel: f.channel,
        channel_token_account: f.channel_ata,
        payer_token_account: f.payer_ata,
        mint: f.mint,
        token_program,
    }
    .instruction();
    let tx = build_focal_tx(&svm, &f.payer, &[], &[ix]);
    record(&mut svm, tx, label).expect("withdraw_payer ok");
}

/// SPL Token `withdraw_payer` on a FINALIZED channel: one-shot refund of
/// `deposit - settled` from escrow to the payer ATA + `payer_withdrawn_at`
/// stamp.
#[test]
fn withdraw_payer_spl() {
    run_withdraw_payer(SPL_TOKEN, "withdraw_payer[tok=spl]");
}

/// Token-2022 `withdraw_payer`. Pins the SPL → T22 cost delta on the
/// payer-refund transfer path.
#[test]
fn withdraw_payer_t22() {
    run_withdraw_payer(TOKEN_2022, "withdraw_payer[tok=t22]");
}
