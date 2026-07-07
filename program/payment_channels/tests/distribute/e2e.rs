//! End-to-end LiteSVM scenarios for `distribute`.
//!
//! Drives the full open → optional `settle` → distribute pipeline against
//! the compiled `.so`.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels::constants::OPEN_SLOT_WINDOW;
use payment_channels::instructions::distribute::DISCRIMINATOR;
use payment_channels::instructions::open::DISCRIMINATOR as OPEN_DISCRIMINATOR;
use payment_channels_client::instructions::{Settle, WithdrawPayer};
use payment_channels_client::types::{
    DistributionEntry, PayoutBeneficiary, PayoutRedirected, RedirectReason,
};
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use spl_token_2022_interface::state::AccountState;

use super::{
    MAX_DISTRIBUTION_RECIPIENTS, STATUS_CLOSING, STATUS_DISTRIBUTED, STATUS_OPEN, STATUS_SEALED,
    Split, TOKEN_2022, build_distribute_ix, build_recipients,
};
use crate::common::events::events;
use crate::common::token_2022::{
    EXT_GROUP_MEMBER_POINTER, EXT_GROUP_POINTER, EXT_IMMUTABLE_OWNER, EXT_MEMO_TRANSFER,
    EXT_METADATA_POINTER, EXT_MINT_CLOSE_AUTHORITY, EXT_TOKEN_GROUP, EXT_TOKEN_GROUP_MEMBER,
    EXT_TOKEN_METADATA, EXT_TRANSFER_FEE_CONFIG, EXT_TRANSFER_HOOK, POINTER_EXTENSION_LEN,
    TOKEN_2022_ACCOUNT_TYPE_ACCOUNT, TOKEN_2022_ACCOUNT_TYPE_OFFSET, TOKEN_2022_BASE_ACCOUNT_LEN,
    TOKEN_2022_TLV_START, TOKEN_GROUP_LEN, TOKEN_GROUP_MEMBER_LEN, TOKEN_METADATA_MIN_LEN,
    add_account_extension, add_mint_extension, close_token_account, set_token_account_owner,
    set_token_account_state,
};
use solana_compute_budget::compute_budget_limits::MAX_COMPUTE_UNIT_LIMIT;
use solana_compute_budget_interface::ComputeBudgetInstruction;

use crate::common::{
    ATA_PROGRAM, INSTRUCTIONS_SYSVAR, PROGRAM_ID, ProgramLoader, SPL_TOKEN, SYSTEM_PROGRAM,
    SYSVAR_RENT, build_reclaim_ix, channel_open_slot, current_slot, event_authority,
    expect_custom_err, expect_instruction_err, mutate_channel, read_channel, set_clock,
    token_balance, treasury_owner,
    voucher::{build_ed25519_ix, voucher, voucher_payload},
    warp_past_close_gate,
};

const GRACE_PERIOD: u32 = 3600;
const DEFAULT_SALT: u64 = 0x1234_5678_9abc_def0;

fn set_token_balance(svm: &mut LiteSVM, token_account: &Pubkey, amount: u64) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    acct.data[64..72].copy_from_slice(&amount.to_le_bytes());
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

fn add_malformed_account_extension(svm: &mut LiteSVM, token_account: &Pubkey) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    if acct.data.len() < TOKEN_2022_TLV_START {
        acct.data.resize(TOKEN_2022_TLV_START, 0);
    }
    acct.data[TOKEN_2022_BASE_ACCOUNT_LEN..TOKEN_2022_ACCOUNT_TYPE_OFFSET].fill(0);
    acct.data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] = TOKEN_2022_ACCOUNT_TYPE_ACCOUNT;
    acct.data.truncate(TOKEN_2022_TLV_START);
    acct.data
        .extend_from_slice(&EXT_IMMUTABLE_OWNER.to_le_bytes());
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

fn read_payout_watermark(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    read_channel(svm, channel, |ch| ch.payout_watermark())
}

/// Assert the full-closure shape of a channel PDA after SEALED
/// `distribute`: every lamport moved to the rent payer and the account
/// reaped by the runtime — `get_account` returns `None`, or an empty
/// 0-lamport system-owned shell if the runtime kept the entry around.
fn assert_fully_closed(svm: &LiteSVM, channel: &Pubkey) {
    match svm.get_account(channel) {
        None => {}
        Some(acct) => {
            assert_eq!(acct.lamports, 0, "closed channel keeps no lamports");
            assert!(acct.data.is_empty(), "closed channel keeps no data");
            assert_eq!(
                acct.owner, SYSTEM_PROGRAM,
                "closed channel reverts to the system program"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Typed mutations to `Channel.status` / `settlement.payout_watermark` /
// `payer_withdrawn_at`.

fn set_status(svm: &mut LiteSVM, channel: &Pubkey, status: u8) {
    mutate_channel(svm, channel, |ch| ch.status = status);
}

fn set_payout_watermark(svm: &mut LiteSVM, channel: &Pubkey, payout_watermark: u64) {
    mutate_channel(svm, channel, |ch| ch.set_payout_watermark(payout_watermark));
}

fn set_payer_withdrawn_at(svm: &mut LiteSVM, channel: &Pubkey, ts: i64) {
    mutate_channel(svm, channel, |ch| ch.set_payer_withdrawn_at(ts));
}

// ---------------------------------------------------------------------------
// Open helpers — full `open` ix submission via real CPI.

fn setup_funded_svm_with_token_program(
    svm: &mut LiteSVM,
    deposit: u64,
    token_program: &Pubkey,
) -> (Keypair, Pubkey, Pubkey) {
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let mint = CreateMint::new(svm, &payer)
        .decimals(0)
        .token_program_id(token_program)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(svm, &payer, &mint)
        .token_program_id(token_program)
        .send()
        .unwrap();
    MintTo::new(svm, &payer, &mint, &payer_ata, deposit)
        .token_program_id(token_program)
        .send()
        .unwrap();
    (payer, mint, payer_ata)
}

/// `open_slot` is a channel PDA seed: the caller must fix it (the same
/// value it will pass in the `open` ix args) before the address is known,
/// and each distinct `open_slot` yields a distinct address.
#[allow(clippy::too_many_arguments)]
fn derive_pdas_with_token_program(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    open_slot: u64,
    token_program: &Pubkey,
) -> (Pubkey, Pubkey) {
    let (channel, _) = Pubkey::find_program_address(
        &[
            b"channel",
            payer.as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
            &open_slot.to_le_bytes(),
        ],
        &PROGRAM_ID,
    );
    let (ata, _) = Pubkey::find_program_address(
        &[channel.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );
    (channel, ata)
}

/// `open` ix data with explicit per-recipient splits — wire-format sibling
/// of `tests/open/mod.rs::open_ix` that lets callers commit a known
/// `distribution_hash` to the channel.
fn open_ix_data_for_splits(
    salt: u64,
    deposit: u64,
    grace_period: u32,
    open_slot: u64,
    splits: &[Split],
) -> Vec<u8> {
    assert!(splits.len() <= MAX_DISTRIBUTION_RECIPIENTS);
    let mut data = vec![OPEN_DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&grace_period.to_le_bytes());
    data.extend_from_slice(&open_slot.to_le_bytes());
    data.extend_from_slice(&(splits.len() as u32).to_le_bytes());
    for s in splits {
        data.extend_from_slice(s.owner.as_ref());
        data.extend_from_slice(&s.bps.to_le_bytes());
    }
    data
}

#[allow(clippy::too_many_arguments)]
fn open_ix_for_splits(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    channel: &Pubkey,
    payer_token_account: &Pubkey,
    channel_token_account: &Pubkey,
    token_program: &Pubkey,
    salt: u64,
    deposit: u64,
    grace_period: u32,
    open_slot: u64,
    splits: &[Split],
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &open_ix_data_for_splits(salt, deposit, grace_period, open_slot, splits),
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*payer, true), // rent_payer (= payer)
            AccountMeta::new_readonly(*payee, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*authorized_signer, false),
            AccountMeta::new(*channel, false),
            AccountMeta::new(*payer_token_account, false),
            AccountMeta::new(*channel_token_account, false),
            AccountMeta::new_readonly(*token_program, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(SYSVAR_RENT, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(event_authority(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

struct OpenedChannel {
    channel: Pubkey,
    channel_ata: Pubkey,
    payee: Pubkey,
    authorized_signer: Keypair,
}

#[allow(clippy::too_many_arguments)]
fn open_channel(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    payer_token_account: &Pubkey,
    salt: u64,
    deposit: u64,
    grace_period: u32,
    splits: &[Split],
    token_program: &Pubkey,
) -> OpenedChannel {
    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new();
    // `open_slot` (freshest valid value: the current slot) is a PDA seed,
    // so it is fixed before derivation and the ix must echo the same value.
    let open_slot = current_slot(svm);
    let (channel, channel_ata) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        mint,
        &authorized_signer.pubkey(),
        salt,
        open_slot,
        token_program,
    );

    let ix = open_ix_for_splits(
        &payer.pubkey(),
        &payee,
        mint,
        &authorized_signer.pubkey(),
        &channel,
        payer_token_account,
        &channel_ata,
        token_program,
        salt,
        deposit,
        grace_period,
        open_slot,
        splits,
    );

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("open should succeed");

    OpenedChannel {
        channel,
        channel_ata,
        payee,
        authorized_signer,
    }
}

// ---------------------------------------------------------------------------
// Settle helper — drives the precompile + settle bundle to advance the
// `settled` watermark.

fn build_settle_ix(channel: &Pubkey) -> Instruction {
    Settle {
        channel: *channel,
        instructions_sysvar: INSTRUCTIONS_SYSVAR,
    }
    .instruction()
}

fn settle_to(
    svm: &mut LiteSVM,
    fee_payer: &Keypair,
    channel: &Pubkey,
    authorized_signer: &Keypair,
    cumulative_amount: u64,
    expires_at: i64,
) {
    // Vouchers are bound to the incarnation through `channel_id` alone:
    // `open_slot` is a PDA seed, so the address IS the epoch.
    let voucher = voucher(*channel, cumulative_amount, expires_at);
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();
    let pubkey = authorized_signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(channel);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[fee_payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("settle should succeed");
}

// ---------------------------------------------------------------------------
// Scenario fixture — owns the SVM and every account a `distribute` call
// needs. `status`, `settlement.payout_watermark`, and `payer_withdrawn_at`
// are mutated through the typed mutators above pending real
// `request_close` / `seal` / `withdraw_payer` instructions.
struct Scenario {
    svm: LiteSVM,
    fee_payer: Keypair,
    mint: Pubkey,
    payer: Pubkey,
    payer_keypair: Keypair,
    payee: Pubkey,
    authorized_signer: Keypair,
    channel: Pubkey,
    channel_ata: Pubkey,
    payer_ata: Pubkey,
    payee_ata: Pubkey,
    treasury_ata: Pubkey,
    token_program: Pubkey,
    recipient_atas: Vec<Pubkey>,
    splits: Vec<Split>,
}

impl Scenario {
    fn build(
        splits: Vec<Split>,
        deposit: u64,
        settled: u64,
        payout_watermark: u64,
        status: u8,
    ) -> Self {
        Self::build_with_token_program(
            splits,
            deposit,
            settled,
            payout_watermark,
            status,
            TOKEN_2022,
        )
    }

    fn build_with_token_program(
        splits: Vec<Split>,
        deposit: u64,
        settled: u64,
        payout_watermark: u64,
        status: u8,
        token_program: Pubkey,
    ) -> Self {
        let mut svm = LiteSVM::load_program();
        let fee_payer = Keypair::new();
        svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&treasury_owner(), 1_000_000_000).unwrap();

        let (payer_kp, mint, payer_ata) =
            setup_funded_svm_with_token_program(&mut svm, deposit, &token_program);
        let payer = payer_kp.pubkey();

        let opened = open_channel(
            &mut svm,
            &payer_kp,
            &mint,
            &payer_ata,
            DEFAULT_SALT,
            deposit,
            GRACE_PERIOD,
            &splits,
            &token_program,
        );
        let channel = opened.channel;
        let channel_ata = opened.channel_ata;

        // Payee ATA must be created here, after `open_channel` mints the
        // payee Pubkey internally — `distribute` is permissionless and only
        // *validates* this account, so any prior caller is responsible for
        // creating it.
        svm.airdrop(&opened.payee, 1_000_000).ok();
        let payee_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&opened.payee)
            .token_program_id(&token_program)
            .send()
            .expect("payee ATA");

        if settled > 0 {
            settle_to(
                &mut svm,
                &fee_payer,
                &channel,
                &opened.authorized_signer,
                settled,
                0,
            );
        }

        if payout_watermark > 0 {
            set_payout_watermark(&mut svm, &channel, payout_watermark);
        }

        if status != STATUS_OPEN {
            mutate_channel(&mut svm, &channel, |ch| ch.status = status);
        }

        // Scenarios built directly in SEALED exist to run the terminal
        // distribute. Advance past the reclaim gate
        // (`clock.slot > open_slot + OPEN_SLOT_WINDOW`) so it takes the fast
        // path and fully deallocates the channel in the same instruction;
        // the in-window two-phase path (`Distributed` + later `reclaim`) is
        // pinned by `sealed_distribute_inside_window_takes_two_phase_path`
        // and the `reclaim` suite.
        if status == STATUS_SEALED {
            warp_past_close_gate(&mut svm, &channel);
        }

        let treasury_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&treasury_owner())
            .token_program_id(&token_program)
            .send()
            .expect("treasury ATA");

        let mut recipient_atas = Vec::with_capacity(splits.len());
        let mut created_recipient_atas = Vec::<(Pubkey, Pubkey)>::new();
        for s in &splits {
            if let Some((_, ata)) = created_recipient_atas
                .iter()
                .find(|(owner, _)| owner == &s.owner)
            {
                recipient_atas.push(*ata);
                continue;
            }
            svm.airdrop(&s.owner, 1_000_000).ok();
            let r_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
                .owner(&s.owner)
                .token_program_id(&token_program)
                .send()
                .expect("recipient ATA");
            created_recipient_atas.push((s.owner, r_ata));
            recipient_atas.push(r_ata);
        }

        Self {
            svm,
            fee_payer,
            mint,
            payer,
            payer_keypair: payer_kp,
            payee: opened.payee,
            authorized_signer: opened.authorized_signer,
            channel,
            channel_ata,
            payer_ata,
            payee_ata,
            treasury_ata,
            token_program,
            recipient_atas,
            splits,
        }
    }

    fn recipients(&self) -> Vec<DistributionEntry> {
        build_recipients(&self.splits)
    }

    fn distribute_ix(&self) -> Instruction {
        build_distribute_ix(
            &self.channel,
            &self.payer,
            &self.channel_ata,
            &self.payer_ata,
            &self.payee_ata,
            &self.treasury_ata,
            &self.mint,
            &self.token_program,
            &self.recipient_atas,
            self.recipients(),
        )
    }

    fn send(&mut self, ix: Instruction) -> litesvm::types::TransactionResult {
        // LiteSVM doesn't auto-advance latest_blockhash, so back-to-back
        // distribute_ix calls would collide on tx signature. Bump once per
        // send so callers can loop without thinking about it.
        self.svm.expire_blockhash();
        let blockhash = self.svm.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(MAX_COMPUTE_UNIT_LIMIT),
                ix,
            ],
            Some(&self.fee_payer.pubkey()),
            &[&self.fee_payer],
            blockhash,
        );
        self.svm.send_transaction(tx)
    }

    /// Versioned-tx path for the N=32 distribute tests. An ALT is always
    /// installed because the worst-case ix exceeds the 32 static-key legacy
    /// limit. `compute_unit_limit` is per-call-site: SPL batched paths fit in
    /// the default 200k cap (`None`); Token-2022 paths overrun it and need
    /// to increase it to `Some(MAX_COMPUTE_UNIT_LIMIT)`.
    fn send_v0_distribute(
        &mut self,
        recipient_atas_for_alt: Vec<Pubkey>,
        compute_unit_limit: Option<u32>,
    ) -> litesvm::types::TransactionResult {
        let (_alt_key, alt_account) = crate::common::lookup_table::install_lookup_table(
            &mut self.svm,
            recipient_atas_for_alt,
        );
        let prefix: Vec<Instruction> = compute_unit_limit
            .map(|units| vec![ComputeBudgetInstruction::set_compute_unit_limit(units)])
            .unwrap_or_default();
        let tx = crate::common::lookup_table::build_v0_transaction_with_prefix(
            &self.svm,
            &self.fee_payer,
            &prefix,
            &[self.distribute_ix()],
            &alt_account,
        );
        self.svm.send_transaction(tx)
    }
}

fn send_withdraw_payer(s: &mut Scenario) {
    let withdraw_ix = WithdrawPayer {
        payer: s.payer_keypair.pubkey(),
        channel: s.channel,
        channel_token_account: s.channel_ata,
        payer_token_account: s.payer_ata,
        mint: s.mint,
        token_program: s.token_program,
    }
    .instruction();
    let tx = Transaction::new_signed_with_payer(
        &[withdraw_ix],
        Some(&s.payer_keypair.pubkey()),
        &[&s.payer_keypair],
        s.svm.latest_blockhash(),
    );
    s.svm.send_transaction(tx).expect("withdraw_payer ok");
}

// ===========================================================================
// Tests

#[test]
fn happy_path_open_splits() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 3000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 1000,
        },
    ];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(
        splits.clone(),
        deposit,
        settled,
        payout_watermark,
        STATUS_OPEN,
    );

    let pool_amount = settled - payout_watermark;
    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 30_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[2]), 10_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 20_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(
        read_payout_watermark(&s.svm, &s.channel),
        payout_watermark + pool_amount
    );
}

#[test]
fn open_flooring_residual_is_accounted_and_carried_forward() {
    // settled=100, splits 2×3333 bps + payee 3334 bps:
    // floor cumulative entitlements are 33 + 33 + 33, with residual=1.
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 3333,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 3333,
        },
    ];
    let deposit = 200;
    let settled = 100;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 33);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 33);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 33);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 101);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn open_partial_flooring_residual_allows_zero_delta_share() {
    // settled=2, split 9000 bps + payee 1000 bps:
    // recipient cumulative floor is 1; payee is still 0.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 9000,
    }];
    let deposit = 20;
    let settled = 2;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 1);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 19);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn open_pool_one_with_50_50_split_accounts_without_transfer() {
    // settled=1, split 5000 bps + payee 5000 bps: both cumulative floors are 0.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 2;
    let settled = 1;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), deposit);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn open_pool_one_then_resettle_to_two_releases_residual() {
    // settled=1 transfers nothing but accounts the watermark. After re-settle
    // to 2, cumulative deltas release the prior residual as 1 + 1.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 2;
    let mut s = Scenario::build(splits, deposit, 1, 0, STATUS_OPEN);

    s.send(s.distribute_ix())
        .expect("settled=1 accounts residual without transfer");
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), 1);

    settle_to(
        &mut s.svm,
        &s.fee_payer,
        &s.channel,
        &s.authorized_signer,
        2,
        0,
    );

    s.send(s.distribute_ix())
        .expect("cumulative 50/50 deltas release residual");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 1);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 1);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), 2);
}

#[test]
fn one_bps_share_releases_at_ten_thousand_settled() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1,
    }];
    let deposit = 10_000;
    let mut s = Scenario::build(splits, deposit, 9_999, 0, STATUS_OPEN);

    s.send(s.distribute_ix())
        .expect("1 bps share remains below whole-token boundary");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 9_998);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 2);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), 9_999);

    settle_to(
        &mut s.svm,
        &s.fee_payer,
        &s.channel,
        &s.authorized_signer,
        10_000,
        0,
    );
    s.send(s.distribute_ix())
        .expect("1 bps share crosses whole-token boundary");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 1);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 9_999);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), 10_000);
}

#[test]
fn sealed_after_open_zero_delta_distribution_refunds_and_sweeps_residual() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 10;
    let settled = 1;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_OPEN);

    s.send(s.distribute_ix())
        .expect("open zero-delta distribution ok");
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), deposit);

    set_status(&mut s.svm, &s.channel, STATUS_SEALED);
    // Warp past the reclaim gate so the terminal distribute takes the fast
    // path and fully deallocates the channel.
    warp_past_close_gate(&mut s.svm, &s.channel);
    s.send(s.distribute_ix())
        .expect("sealed zero-delta close ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), settled);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn sealed_after_withdraw_payer_sweeps_open_zero_delta_residual_once() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 10;
    let settled = 1;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_OPEN);

    s.send(s.distribute_ix())
        .expect("open zero-delta distribution ok");
    set_status(&mut s.svm, &s.channel, STATUS_SEALED);
    // Warp past the reclaim gate so the terminal distribute takes the fast
    // path and fully deallocates the channel.
    warp_past_close_gate(&mut s.svm, &s.channel);

    set_clock(&mut s.svm, 1_000_000);
    send_withdraw_payer(&mut s);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);

    s.send(s.distribute_ix())
        .expect("sealed residual sweep after withdraw ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), settled);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn repeated_open_micro_distributes_match_single_final_distribution() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 100;
    let mut s = Scenario::build(splits, deposit, 0, 0, STATUS_OPEN);

    for cumulative_amount in 1..=100 {
        settle_to(
            &mut s.svm,
            &s.fee_payer,
            &s.channel,
            &s.authorized_signer,
            cumulative_amount,
            0,
        );
        s.send(s.distribute_ix())
            .expect("micro distribute should not grind residual");
        assert_eq!(read_payout_watermark(&s.svm, &s.channel), cumulative_amount);
    }

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 50);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 0);

    set_status(&mut s.svm, &s.channel, STATUS_SEALED);
    // Warp past the reclaim gate so the terminal distribute takes the fast
    // path and fully deallocates the channel.
    warp_past_close_gate(&mut s.svm, &s.channel);
    s.send(s.distribute_ix()).expect("sealed distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 50);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn uneven_three_share_micro_distributes_preserve_cumulative_entitlements() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 3333,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 3333,
        },
    ];
    let deposit = 6;
    let mut s = Scenario::build(splits, deposit, 0, 0, STATUS_OPEN);

    for cumulative_amount in 1..=6 {
        settle_to(
            &mut s.svm,
            &s.fee_payer,
            &s.channel,
            &s.authorized_signer,
            cumulative_amount,
            0,
        );
        s.send(s.distribute_ix())
            .expect("uneven three-share micro distribute ok");
        assert_eq!(read_payout_watermark(&s.svm, &s.channel), cumulative_amount);
    }

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 1);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 1);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 2);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 2);

    set_status(&mut s.svm, &s.channel, STATUS_SEALED);
    // Warp past the reclaim gate so the terminal distribute takes the fast
    // path and fully deallocates the channel.
    warp_past_close_gate(&mut s.svm, &s.channel);
    s.send(s.distribute_ix()).expect("sealed distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 1);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 1);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 2);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 2);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn happy_path_open_splits_spl_token() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 2500,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 2500,
        },
    ];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_OPEN,
        SPL_TOKEN,
    );

    s.send(s.distribute_ix()).expect("spl distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn happy_path_sealed_close() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(
        splits.clone(),
        deposit,
        settled,
        payout_watermark,
        STATUS_SEALED,
    );

    let payer_balance_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);

    assert_fully_closed(&s.svm, &s.channel);

    // Payer recovers the ENTIRE channel-account balance (full closure) plus
    // the escrow ATA rent.
    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    assert_eq!(
        payer_after - payer_balance_before,
        channel_lamports_before + channel_ata_lamports_before
    );
}

#[test]
fn happy_path_sealed_close_spl_token() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_SEALED,
        SPL_TOKEN,
    );

    s.send(s.distribute_ix()).expect("spl sealed ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn distribute_after_withdraw_payer_skips_payer_refund() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s =
        Scenario::build_with_token_program(splits, deposit, settled, 0, STATUS_SEALED, SPL_TOKEN);

    // Advance the clock so withdraw_payer stamps a non-zero payer_withdrawn_at.
    set_clock(&mut s.svm, 1_000_000);

    // Payer claims their deposit − settled refund first.
    send_withdraw_payer(&mut s);

    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);

    // distribute should succeed and only pay out the settled pool —
    // no second refund to payer.
    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn sealed_zero_pool_still_refunds_and_closes() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 100_000;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_SEALED);

    set_token_balance(&mut s.svm, &s.channel_ata, deposit - settled);

    s.send(s.distribute_ix()).expect("sealed zero pool ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn sealed_sweeps_final_flooring_residual_to_treasury() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 3333,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 3333,
        },
    ];
    let deposit = 250;
    let settled = 150;
    let payout_watermark = 100;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_SEALED);

    set_token_balance(&mut s.svm, &s.channel_ata, deposit - payout_watermark + 1);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 16);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 16);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 17);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 2);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn happy_path_sealed_already_withdrawn() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_SEALED);

    set_payer_withdrawn_at(&mut s.svm, &s.channel, 1_700_000_000);
    set_token_balance(&mut s.svm, &s.channel_ata, settled - payout_watermark);

    let payer_balance_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_fully_closed(&s.svm, &s.channel);

    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    assert_eq!(
        payer_after - payer_balance_before,
        channel_lamports_before + channel_ata_lamports_before
    );
}

#[test]
fn bad_preimage_hash() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);

    mutate_channel(&mut s.svm, &s.channel, |ch| {
        ch.distribution_hash[0] ^= 0xFF;
    });
    let res = s.send(s.distribute_ix());
    expect_custom_err(res, PaymentChannelsError::InvalidDistributionHash);
}

#[test]
fn token_2022_allowed_mint_extensions_succeed() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    for (extension_type, value_len) in [
        (EXT_METADATA_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_METADATA, TOKEN_METADATA_MIN_LEN),
        (EXT_GROUP_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP, TOKEN_GROUP_LEN),
        (EXT_GROUP_MEMBER_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP_MEMBER, TOKEN_GROUP_MEMBER_LEN),
    ] {
        add_mint_extension(&mut s.svm, &s.mint, extension_type, value_len);
    }

    s.send(s.distribute_ix()).expect("allowed extensions ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn unsupported_token_2022_mint_extensions_reject_without_state_changes() {
    for (extension_type, value_len) in [
        (EXT_TRANSFER_FEE_CONFIG, 108),
        (EXT_TRANSFER_HOOK, 64),
        (EXT_MINT_CLOSE_AUTHORITY, 32),
    ] {
        let splits = vec![Split {
            owner: Pubkey::new_unique(),
            bps: 5000,
        }];
        let deposit = 200_000;
        let settled = 100_000;
        let payout_watermark = 0;
        let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
        let payout_watermark_before = read_payout_watermark(&s.svm, &s.channel);
        add_mint_extension(&mut s.svm, &s.mint, extension_type, value_len);

        let res = s.send(s.distribute_ix());

        expect_custom_err(res, PaymentChannelsError::MalformedMintTokenExtensions);
        assert_eq!(
            read_payout_watermark(&s.svm, &s.channel),
            payout_watermark_before
        );
        assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
        assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    }
}

#[test]
fn malformed_token_2022_account_extension_rejects_without_state_changes() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let payout_watermark_before = read_payout_watermark(&s.svm, &s.channel);
    add_malformed_account_extension(&mut s.svm, &s.recipient_atas[0]);

    let res = s.send(s.distribute_ix());

    expect_custom_err(res, PaymentChannelsError::InvalidRecipientTokenExtensions);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(
        read_payout_watermark(&s.svm, &s.channel),
        payout_watermark_before
    );
}

// ===========================================================================
// Skip-and-redirect: unsupported Token-2022 beneficiary account extensions
// forfeit only the affected nonzero share to treasury.

#[test]
fn poisoned_recipient_redirects_share_to_treasury_in_open() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 3000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
    ];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let poisoned_owner = s.splits[0].owner;
    add_account_extension(&mut s.svm, &s.recipient_atas[0], EXT_MEMO_TRANSFER, 1);

    let meta = s
        .send(s.distribute_ix())
        .expect("poisoned recipient forfeits, distribute still succeeds");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 30_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 30_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);

    // The forfeit is observable as a single typed redirect event.
    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: poisoned_owner,
            amount: 30_000,
            beneficiary: PayoutBeneficiary::Recipient,
            reason: RedirectReason::UnsupportedExtension,
        }],
    );
}

#[test]
fn closed_recipient_ata_redirects_share_to_treasury_in_open() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 3000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
    ];
    let deposit = 200_000;
    let settled = 100_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_OPEN);
    let poisoned_owner = s.splits[0].owner;
    close_token_account(&mut s.svm, &s.recipient_atas[0]);

    let meta = s
        .send(s.distribute_ix())
        .expect("closed recipient ATA forfeits its share; distribute still succeeds");

    // (recipient_atas[0] data is gone, so only the survivors are asserted.)
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 30_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 30_000);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);

    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: poisoned_owner,
            amount: 30_000,
            beneficiary: PayoutBeneficiary::Recipient,
            reason: RedirectReason::ClosedOrMalformed,
        }],
    );
}

#[test]
fn frozen_recipient_ata_redirects_share_to_treasury_in_open() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 3000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
    ];
    let deposit = 200_000;
    let settled = 100_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_OPEN);
    let poisoned_owner = s.splits[0].owner;
    set_token_account_state(&mut s.svm, &s.recipient_atas[0], AccountState::Frozen);

    let meta = s
        .send(s.distribute_ix())
        .expect("frozen recipient ATA forfeits its share; distribute still succeeds");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 30_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 30_000);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);

    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: poisoned_owner,
            amount: 30_000,
            beneficiary: PayoutBeneficiary::Recipient,
            reason: RedirectReason::NotInitialized,
        }],
    );
}

// A recipient that reassigns its canonical ATA owner via
// `SetAuthority(AccountOwner)` must not be able to brick `distribute`. The
// canonical address still matches, but the parsed owner field no longer equals
// the recipient, so the share forfeits to treasury (`ReassignedAuthority`)
// instead of failing fatally — the watermark advances and other legs are paid.
#[test]
fn reassigned_recipient_ata_owner_redirects_share_to_treasury_in_open() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 3000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
    ];
    let deposit = 200_000;
    let settled = 100_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_OPEN);
    let poisoned_owner = s.splits[0].owner;
    set_token_account_owner(&mut s.svm, &s.recipient_atas[0], &Pubkey::new_unique());

    let meta = s
        .send(s.distribute_ix())
        .expect("reassigned recipient ATA owner forfeits its share; distribute still succeeds");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 30_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 30_000);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);

    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: poisoned_owner,
            amount: 30_000,
            beneficiary: PayoutBeneficiary::Recipient,
            reason: RedirectReason::ReassignedAuthority,
        }],
    );
}

// A poisoned recipient must not block the sealed close. The
// reassigned-owner share forfeits to treasury and the channel closes, draining
// the escrow and deallocating the PDA.
#[test]
fn reassigned_recipient_ata_owner_redirects_and_closes_in_sealed() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_SEALED);
    let poisoned_owner = s.splits[0].owner;
    set_token_account_owner(&mut s.svm, &s.recipient_atas[0], &Pubkey::new_unique());

    let meta = s
        .send(s.distribute_ix())
        .expect("reassigned recipient ATA owner forfeits its share; close completes");

    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 75_000);
    assert_fully_closed(&s.svm, &s.channel);

    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: poisoned_owner,
            amount: 75_000,
            beneficiary: PayoutBeneficiary::Recipient,
            reason: RedirectReason::ReassignedAuthority,
        }],
    );
}

// A payee that reassigns its canonical ATA owner via
// `SetAuthority(AccountOwner)` must not be able to brick `distribute`. The
// canonical address still matches, but the parsed owner field no longer equals
// the payee, so the remainder forfeits to treasury (`ReassignedAuthority`)
// instead of failing fatally — the watermark advances and the recipient is paid.
#[test]
fn reassigned_payee_ata_owner_redirects_remainder_to_treasury_in_open() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 6000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    set_token_account_owner(&mut s.svm, &s.payee_ata, &Pubkey::new_unique());

    let meta = s
        .send(s.distribute_ix())
        .expect("reassigned payee ATA owner forfeits remainder; distribute still succeeds");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 60_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 40_000);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);

    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: s.payee,
            amount: 40_000,
            beneficiary: PayoutBeneficiary::Payee,
            reason: RedirectReason::ReassignedAuthority,
        }],
    );
}

// A payer that reassigns its canonical refund ATA owner via
// `SetAuthority(AccountOwner)` must not be able to brick the sealed close.
// The refund forfeits to treasury (`ReassignedAuthority`) and the channel
// closes; the recipient and payee legs are paid normally.
#[test]
fn reassigned_payer_ata_owner_redirects_refund_to_treasury_in_sealed() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_SEALED);
    set_token_account_owner(&mut s.svm, &s.payer_ata, &Pubkey::new_unique());

    let meta = s
        .send(s.distribute_ix())
        .expect("reassigned payer ATA owner forfeits refund; close completes");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), deposit - settled);
    assert_fully_closed(&s.svm, &s.channel);

    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: s.payer,
            amount: deposit - settled,
            beneficiary: PayoutBeneficiary::Payer,
            reason: RedirectReason::ReassignedAuthority,
        }],
    );
}

#[test]
fn frozen_payer_ata_redirects_refund_to_treasury_in_sealed() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_SEALED);
    set_token_account_state(&mut s.svm, &s.payer_ata, AccountState::Frozen);

    let meta = s
        .send(s.distribute_ix())
        .expect("frozen payer ATA forfeits refund; close completes");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), deposit - settled);
    assert_fully_closed(&s.svm, &s.channel);

    assert_eq!(
        events::<PayoutRedirected>(&meta),
        vec![PayoutRedirected {
            channel: s.channel,
            owner: s.payer,
            amount: deposit - settled,
            beneficiary: PayoutBeneficiary::Payer,
            reason: RedirectReason::NotInitialized,
        }],
    );
}

#[test]
fn poisoned_payee_redirects_remainder_to_treasury_in_open() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 6000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    add_account_extension(&mut s.svm, &s.payee_ata, EXT_MEMO_TRANSFER, 1);

    s.send(s.distribute_ix())
        .expect("poisoned payee forfeits remainder");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 60_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 40_000);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn zero_share_poisoned_payee_does_not_block_recipient_only_open_distribute() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 10_000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    add_account_extension(&mut s.svm, &s.payee_ata, EXT_MEMO_TRANSFER, 1);

    s.send(s.distribute_ix())
        .expect("zero-share poisoned payee must not block recipient-only distribute");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), settled);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn zero_share_poisoned_payee_does_not_block_recipient_only_sealed_distribute() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 10_000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_SEALED);
    add_account_extension(&mut s.svm, &s.payee_ata, EXT_MEMO_TRANSFER, 1);

    s.send(s.distribute_ix())
        .expect("zero-share poisoned payee must not block sealed close");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), settled);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn poisoned_payer_ata_does_not_affect_open_distribute() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    add_account_extension(&mut s.svm, &s.payer_ata, EXT_MEMO_TRANSFER, 1);

    s.send(s.distribute_ix())
        .expect("poisoned payer ATA must not block OPEN distribute");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn poisoned_payer_ata_redirects_refund_to_treasury_in_sealed_with_refund() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_SEALED);
    add_account_extension(&mut s.svm, &s.payer_ata, EXT_MEMO_TRANSFER, 1);

    s.send(s.distribute_ix())
        .expect("poisoned payer ATA forfeits refund; close completes");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), deposit - settled);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn num_recipients_zero_pays_full_pool_to_payee() {
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(vec![], deposit, settled, payout_watermark, STATUS_OPEN);

    let pool_amount = settled - payout_watermark;
    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.payee_ata), pool_amount);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), pool_amount);
}

#[test]
fn wrong_recipient_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .token_program_id(&s.token_program)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &[rogue_ata],
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::RecipientAccountMismatch);
}

#[test]
fn wrong_treasury_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .token_program_id(&s.token_program)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &rogue_ata,
        &s.mint,
        &s.token_program,
        &s.recipient_atas,
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::TreasuryAccountMismatch);
}

#[test]
fn wrong_token_program() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let system_id = Pubkey::default();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &s.treasury_ata,
        &s.mint,
        &system_id,
        &s.recipient_atas,
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidMintTokenProgram);
}

#[test]
fn pool_zero_rejects() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 0, STATUS_OPEN);
    expect_custom_err(
        s.send(s.distribute_ix()),
        PaymentChannelsError::NothingToDistribute,
    );
}

#[test]
fn status_closing_rejects() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_CLOSING);
    expect_custom_err(
        s.send(s.distribute_ix()),
        PaymentChannelsError::ChannelNotDistributable,
    );
}

#[test]
fn num_recipients_exceeds_max() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);

    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&33u32.to_le_bytes());
    for _ in 0..33 {
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&1000u16.to_le_bytes());
    }
    let metas = vec![
        AccountMeta::new(s.channel, false),
        AccountMeta::new(s.payer, false),
        AccountMeta::new(s.channel_ata, false),
        AccountMeta::new(s.payer_ata, false),
        AccountMeta::new(s.payee_ata, false),
        AccountMeta::new(s.treasury_ata, false),
        AccountMeta::new_readonly(s.mint, false),
        AccountMeta::new_readonly(s.token_program, false),
    ];
    let ix = Instruction::new_with_bytes(PROGRAM_ID, &data, metas);
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidRecipientCount);
}

#[test]
fn recipient_tail_length_mismatch_rejects() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &[],
        s.recipients(),
    );
    expect_custom_err(
        s.send(ix),
        PaymentChannelsError::RecipientAccountCountMismatch,
    );
}

#[test]
fn bps_sum_equals_10000_no_payee_share() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 6000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
    ];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 60_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn bps_sum_equals_10000_still_validates_payee_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 10_000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .token_program_id(&s.token_program)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &rogue_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &s.recipient_atas,
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::PayeeAccountMismatch);
}

#[test]
fn wrong_payee_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .token_program_id(&s.token_program)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &rogue_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &s.recipient_atas,
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::PayeeAccountMismatch);
}

#[test]
fn many_distinct_recipients_accepted() {
    // Cap of 32 recipients is exercised by `tests/open` arg-validation;
    // here 16 is comfortably within legacy tx size and exercises the same
    // ATA-tail loop end-to-end.
    const N: usize = 16;
    let splits: Vec<Split> = (0..N)
        .map(|_| Split {
            owner: Pubkey::new_unique(),
            bps: 1,
        })
        .collect();
    let deposit = 2_000_000;
    let settled = 1_000_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(s.recipient_atas.len(), N);
    let unique: std::collections::HashSet<_> = s.recipient_atas.iter().collect();
    assert_eq!(unique.len(), N);
    for ata in &s.recipient_atas {
        assert_eq!(token_balance(&s.svm, ata), 100);
    }
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn happy_path_spl_token_max_recipients_plus_payee() {
    // SPL batched chunking at N=32 recipients + payee = 33 logical slots
    // across 5 chunks (8+8+8+8+1).
    const N: usize = MAX_DISTRIBUTION_RECIPIENTS;
    const RECIPIENT_BPS: u16 = 100;
    let splits: Vec<Split> = (0..N)
        .map(|_| Split {
            owner: Pubkey::new_unique(),
            bps: RECIPIENT_BPS,
        })
        .collect();
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_OPEN,
        SPL_TOKEN,
    );

    s.send_v0_distribute(s.recipient_atas.clone(), None)
        .expect("spl distribute max recipients ok");

    assert_eq!(s.recipient_atas.len(), N);
    let unique: std::collections::HashSet<_> = s.recipient_atas.iter().collect();
    assert_eq!(unique.len(), N);
    for ata in &s.recipient_atas {
        assert_eq!(token_balance(&s.svm, ata), 1_000);
    }
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 68_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), deposit - settled);
    assert_eq!(read_payout_watermark(&s.svm, &s.channel), settled);
}

#[test]
fn happy_path_spl_token_sealed_max_recipients_plus_payee_refund_sweep() {
    // Worst-case SEALED distribute: every payout phase present —
    // N=32 recipients + payee + payer refund + sweep = 35 logical slots
    // across 5 chunks (8+8+8+8+3), followed by a standalone escrow-close CPI
    // in the shared close tail.
    const N: usize = MAX_DISTRIBUTION_RECIPIENTS;
    const RECIPIENT_BPS: u16 = 100;
    let splits: Vec<Split> = (0..N)
        .map(|_| Split {
            owner: Pubkey::new_unique(),
            bps: RECIPIENT_BPS,
        })
        .collect();
    let deposit: u64 = 200_000;
    let settled: u64 = 99_999;
    let payout_watermark: u64 = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_SEALED,
        SPL_TOKEN,
    );

    let escrow_before = token_balance(&s.svm, &s.channel_ata);
    let payer_sol_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send_v0_distribute(s.recipient_atas.clone(), None)
        .expect("spl sealed max recipients ok");

    let expected_per_recipient: u64 = 999;
    let expected_payee: u64 = 67_999;
    let expected_payer_refund: u64 = deposit - settled;
    let expected_treasury_sweep: u64 =
        escrow_before - 32 * expected_per_recipient - expected_payee - expected_payer_refund;
    assert_eq!(expected_treasury_sweep, 32);

    assert_eq!(s.recipient_atas.len(), N);
    let unique: std::collections::HashSet<_> = s.recipient_atas.iter().collect();
    assert_eq!(unique.len(), N);
    for ata in &s.recipient_atas {
        assert_eq!(token_balance(&s.svm, ata), expected_per_recipient);
    }
    assert_eq!(token_balance(&s.svm, &s.payee_ata), expected_payee);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), expected_payer_refund);
    assert_eq!(
        token_balance(&s.svm, &s.treasury_ata),
        expected_treasury_sweep
    );

    assert_fully_closed(&s.svm, &s.channel);

    // Payer recovers the entire channel-account balance + escrow-ATA rent on
    // the SOL leg.
    let payer_sol_after = s.svm.get_account(&s.payer).unwrap().lamports;
    assert_eq!(
        payer_sol_after - payer_sol_before,
        channel_lamports_before + channel_ata_lamports_before
    );
}

#[test]
fn spl_token_sealed_zero_pool_still_refunds_and_closes() {
    // pool == 0: recipient slots zero-skip and payee has no payable amount;
    // only payer refund, sweep, and close phases run.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 100_000;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_SEALED,
        SPL_TOKEN,
    );

    // Simulate the post-OPEN escrow balance: just the refund headroom left.
    set_token_balance(&mut s.svm, &s.channel_ata, deposit - settled);

    s.send(s.distribute_ix()).expect("spl sealed zero pool ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn spl_token_sealed_already_withdrawn() {
    // `payer_withdrawn_at != 0` skips payer refund when pool > 0.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_SEALED,
        SPL_TOKEN,
    );

    // Simulate post-`withdraw_payer` state: stamp + trim escrow accordingly.
    mutate_channel(&mut s.svm, &s.channel, |ch| {
        ch.set_payer_withdrawn_at(1_700_000_000)
    });
    set_token_balance(&mut s.svm, &s.channel_ata, settled - payout_watermark);

    s.send(s.distribute_ix())
        .expect("spl sealed already-withdrawn ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn spl_token_sealed_chunk_boundary() {
    // N=7 recipients + payee = 8 exactly fills one chunk; the SEALED
    // tail (refund + sweep) spills into a second chunk of 2, followed by a
    // standalone escrow-close CPI in the shared close tail.
    const N: usize = 7;
    const RECIPIENT_BPS: u16 = 1000;
    let splits: Vec<Split> = (0..N)
        .map(|_| Split {
            owner: Pubkey::new_unique(),
            bps: RECIPIENT_BPS,
        })
        .collect();
    let deposit: u64 = 200_000;
    let settled: u64 = 99_999;
    let payout_watermark: u64 = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_SEALED,
        SPL_TOKEN,
    );

    let escrow_before = token_balance(&s.svm, &s.channel_ata);
    let payer_sol_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix())
        .expect("spl sealed chunk-boundary ok");

    let expected_per_recipient: u64 = 9_999;
    let expected_payee: u64 = 29_999;
    let expected_payer_refund: u64 = deposit - settled;
    let expected_treasury_sweep: u64 = escrow_before
        - (N as u64) * expected_per_recipient
        - expected_payee
        - expected_payer_refund;
    assert_eq!(expected_treasury_sweep, 7);

    for ata in &s.recipient_atas {
        assert_eq!(token_balance(&s.svm, ata), expected_per_recipient);
    }
    assert_eq!(token_balance(&s.svm, &s.payee_ata), expected_payee);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), expected_payer_refund);
    assert_eq!(
        token_balance(&s.svm, &s.treasury_ata),
        expected_treasury_sweep
    );
    assert_fully_closed(&s.svm, &s.channel);

    let payer_sol_after = s.svm.get_account(&s.payer).unwrap().lamports;
    assert_eq!(
        payer_sol_after - payer_sol_before,
        channel_lamports_before + channel_ata_lamports_before
    );
}

#[test]
fn token_2022_max_recipients_plus_payee_sealed() {
    // Token-2022 uses direct TransferChecked CPIs (no SPL Batch); worst case
    // is 32 recipients + payee + refund + sweep = 35 CPIs before close.
    const N: usize = MAX_DISTRIBUTION_RECIPIENTS;
    const RECIPIENT_BPS: u16 = 100;
    let splits: Vec<Split> = (0..N)
        .map(|_| Split {
            owner: Pubkey::new_unique(),
            bps: RECIPIENT_BPS,
        })
        .collect();
    let deposit: u64 = 200_000;
    let settled: u64 = 99_999;
    let payout_watermark: u64 = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        payout_watermark,
        STATUS_SEALED,
        TOKEN_2022,
    );

    let escrow_before = token_balance(&s.svm, &s.channel_ata);
    // Token-2022 SEALED at N=32 needs to increase compute budget limit; default CU cap (200k) is too low.
    s.send_v0_distribute(s.recipient_atas.clone(), Some(MAX_COMPUTE_UNIT_LIMIT))
        .expect("token-2022 max recipients ok");

    let expected_per_recipient: u64 = 999;
    let expected_payee: u64 = 67_999;
    let expected_payer_refund: u64 = deposit - settled;
    let expected_treasury_sweep: u64 =
        escrow_before - 32 * expected_per_recipient - expected_payee - expected_payer_refund;
    assert_eq!(expected_treasury_sweep, 32);

    for ata in &s.recipient_atas {
        assert_eq!(token_balance(&s.svm, ata), expected_per_recipient);
    }
    assert_eq!(token_balance(&s.svm, &s.payee_ata), expected_payee);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), expected_payer_refund);
    assert_eq!(
        token_balance(&s.svm, &s.treasury_ata),
        expected_treasury_sweep
    );
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn spl_token_legacy_tx_rejects_max_recipients() {
    const N: usize = MAX_DISTRIBUTION_RECIPIENTS;
    let splits: Vec<Split> = (0..N)
        .map(|_| Split {
            owner: Pubkey::new_unique(),
            bps: 100,
        })
        .collect();
    let mut s =
        Scenario::build_with_token_program(splits, 200_000, 100_000, 0, STATUS_OPEN, SPL_TOKEN);

    // Legacy txs with 40 instruction accounts exceed the static key budget;
    // LiteSVM rejects the message during compute-budget sanitization.
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.send(s.distribute_ix())));
    match outcome {
        Err(_) => {}
        Ok(res) => assert!(res.is_err(), "legacy tx should fail at N=32 without ALT"),
    }
}

// ===========================================================================
// LiteSVM-only full-closure lifecycle tests. These scenarios exercise
// behavior that needs a real SVM:
//   - the Ed25519 precompile + `Instructions` sysvar (settle),
//   - the system program's Transfer+Allocate+Assign path through `open`'s
//     CPI chain (a fresh incarnation opened after full closure),
//   - and the Clock-driven close gate.

/// Drive a Scenario to SEALED with one 50/50 split, then run the terminal
/// distribute to fully deallocate the channel PDA. Returns the scenario plus
/// the closed incarnation's `open_slot` (a PDA seed of the now-dead
/// `s.channel` address) for reincarnation tests.
fn sealed_then_fully_closed() -> (Scenario, u64) {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_SEALED);
    let closed_epoch = channel_open_slot(&s.svm, &s.channel);
    s.send(s.distribute_ix()).expect("distribute ok");
    assert_fully_closed(&s.svm, &s.channel);
    (s, closed_epoch)
}

/// `[ed25519, settle]` pair for an explicit voucher and settle target —
/// unlike `settle_to`, the voucher's `channel_id` and the targeted account
/// can diverge, so callers can present a dead incarnation's voucher against
/// a live channel (or settle a dead address).
fn settle_pair_for(
    s: &Scenario,
    voucher: &payment_channels_client::types::VoucherArgs,
    target: &Pubkey,
) -> [Instruction; 2] {
    let payload = voucher_payload(voucher);
    let signature: [u8; 64] = s.authorized_signer.sign_message(&payload).into();
    let pubkey = s.authorized_signer.pubkey().to_bytes();
    [
        build_ed25519_ix(&pubkey, &signature, &payload),
        build_settle_ix(target),
    ]
}

#[test]
fn settle_on_closed_channel_rejects() {
    let (mut s, _closed_epoch) = sealed_then_fully_closed();

    // A voucher that was valid against the closed incarnation. The PDA is
    // fully deallocated, so the runtime hands settle a 0-lamport system-owned
    // shell and the channel owner check fails before any voucher logic runs.
    let voucher = voucher(s.channel, 1, 0);
    let ixs = settle_pair_for(&s, &voucher, &s.channel);

    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&s.fee_payer.pubkey()),
        &[&s.fee_payer],
        blockhash,
    );
    expect_instruction_err(
        s.svm.send_transaction(tx),
        InstructionError::InvalidAccountOwner,
    );
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn reopen_same_tuple_after_close_lands_at_new_address_and_old_voucher_dies() {
    let (mut s, closed_epoch) = sealed_then_fully_closed();
    let old_channel = s.channel;

    // The SEALED close refunded `deposit - settled` (= 50_000) tokens to
    // the payer ATA; redeposit part of it into the fresh incarnation.
    let new_deposit: u64 = 40_000;

    // (a) A fresh `open` on the same (payer, payee, mint, signer, salt)
    // tuple must succeed — but `open_slot` is a PDA seed, so the new
    // incarnation lands at a NEW address by construction. The close gate
    // forced `clock.slot > closed_epoch + OPEN_SLOT_WINDOW`, so the old
    // address (whose seeds carry `closed_epoch`) can never be re-derived:
    // "reopen at the same address" is impossible, period.
    let reopen_slot = current_slot(&s.svm);
    assert!(reopen_slot > closed_epoch + OPEN_SLOT_WINDOW);
    let (new_channel, new_channel_ata) = derive_pdas_with_token_program(
        &s.payer,
        &s.payee,
        &s.mint,
        &s.authorized_signer.pubkey(),
        DEFAULT_SALT,
        reopen_slot,
        &s.token_program,
    );
    assert_ne!(
        new_channel, old_channel,
        "same tuple + new open_slot seed = new address"
    );
    let open_ix = open_ix_for_splits(
        &s.payer,
        &s.payee,
        &s.mint,
        &s.authorized_signer.pubkey(),
        &new_channel,
        &s.payer_ata,
        &new_channel_ata,
        &s.token_program,
        DEFAULT_SALT,
        new_deposit,
        GRACE_PERIOD,
        reopen_slot,
        &s.splits,
    );
    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[open_ix],
        Some(&s.payer_keypair.pubkey()),
        &[&s.payer_keypair],
        blockhash,
    );
    s.svm
        .send_transaction(tx)
        .expect("reopen of the same tuple after full close should succeed");
    assert_eq!(channel_open_slot(&s.svm, &new_channel), reopen_slot);
    read_channel(&s.svm, &new_channel, |ch| {
        assert_eq!(ch.status, STATUS_OPEN, "fresh incarnation starts OPEN");
        assert_eq!(ch.deposit(), new_deposit);
        assert_eq!(ch.settled(), 0, "watermark does not carry over");
    });
    // The old address stays a dead shell — nothing was resurrected there.
    assert_fully_closed(&s.svm, &old_channel);

    // (b) A voucher minted for the DEAD incarnation presented against the
    // NEW channel: correctly signed, monotonic, under deposit — but its
    // `channel_id` is the old address, and since `open_slot` rides in the
    // seeds, that address binding IS the epoch check.
    let stale = voucher(old_channel, 1_000, 0);
    let ixs = settle_pair_for(&s, &stale, &new_channel);
    s.svm.expire_blockhash();
    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&s.fee_payer.pubkey()),
        &[&s.fee_payer],
        blockhash,
    );
    expect_custom_err(
        s.svm.send_transaction(tx),
        PaymentChannelsError::VoucherChannelMismatch,
    );
    read_channel(&s.svm, &new_channel, |ch| {
        assert_eq!(
            ch.settled(),
            0,
            "dead incarnation's voucher must not settle"
        );
    });

    // (c) Settling the OLD address with its own (channel-matching) voucher
    // is equally dead: the account is a 0-lamport system-owned shell, so
    // the owner check fails before any voucher logic runs.
    let ixs = settle_pair_for(&s, &stale, &old_channel);
    s.svm.expire_blockhash();
    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&s.fee_payer.pubkey()),
        &[&s.fee_payer],
        blockhash,
    );
    expect_instruction_err(
        s.svm.send_transaction(tx),
        InstructionError::InvalidAccountOwner,
    );

    // (d) A voucher bound to the new address settles normally.
    settle_to(
        &mut s.svm,
        &s.fee_payer,
        &new_channel,
        &s.authorized_signer,
        2_000,
        0,
    );
    read_channel(&s.svm, &new_channel, |ch| {
        assert_eq!(ch.settled(), 2_000, "live incarnation's voucher settles");
    });
}

#[test]
fn reopen_after_close_unaffected_by_lamports_donated_to_dead_address() {
    let (mut s, _closed_epoch) = sealed_then_fully_closed();
    let old_channel = s.channel;

    // Griefing attempt: park lamports on the dead address between close and
    // the next open. Since `open_slot` is a PDA seed, the fresh incarnation
    // lands at a NEW address anyway — the donation cannot even touch it.
    // (Prefund tolerance of the *live* target address is pinned separately
    // by `open::e2e::open_succeeds_with_prefunded_channel_pda_lamports`.)
    let donation: u64 = 1_000_000;
    s.svm
        .airdrop(&old_channel, donation)
        .expect("donate to dead channel address");

    let new_deposit: u64 = 40_000;
    let reopen_slot = current_slot(&s.svm);
    let (new_channel, new_channel_ata) = derive_pdas_with_token_program(
        &s.payer,
        &s.payee,
        &s.mint,
        &s.authorized_signer.pubkey(),
        DEFAULT_SALT,
        reopen_slot,
        &s.token_program,
    );
    assert_ne!(new_channel, old_channel);
    let open_ix = open_ix_for_splits(
        &s.payer,
        &s.payee,
        &s.mint,
        &s.authorized_signer.pubkey(),
        &new_channel,
        &s.payer_ata,
        &new_channel_ata,
        &s.token_program,
        DEFAULT_SALT,
        new_deposit,
        GRACE_PERIOD,
        reopen_slot,
        &s.splits,
    );
    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[open_ix],
        Some(&s.payer_keypair.pubkey()),
        &[&s.payer_keypair],
        blockhash,
    );
    s.svm
        .send_transaction(tx)
        .expect("open of the fresh incarnation ignores the dead address entirely");
    assert_eq!(channel_open_slot(&s.svm, &new_channel), reopen_slot);
    read_channel(&s.svm, &new_channel, |ch| {
        assert_eq!(ch.status, STATUS_OPEN);
        assert_eq!(ch.deposit(), new_deposit);
    });

    // The donation is simply stranded on the dead system-owned address —
    // harmless to the protocol, unrecoverable by the program (which will
    // never own that address again).
    let dead = s
        .svm
        .get_account(&old_channel)
        .expect("donated shell exists");
    assert_eq!(dead.lamports, donation, "donation stranded on dead address");
    assert!(dead.data.is_empty(), "dead address holds no channel data");
    assert_eq!(dead.owner, SYSTEM_PROGRAM);
}

#[test]
fn sealed_distribute_inside_window_takes_two_phase_path() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    // Built in OPEN so the fixture does not auto-warp past the gate.
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_OPEN);
    let open_slot = channel_open_slot(&s.svm, &s.channel);

    // OPEN-state (partial) distribute is never gated: it only advances the
    // watermark and cannot deallocate, so running inside the window is fine.
    s.send(s.distribute_ix())
        .expect("open distribute inside the window ok");
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);

    set_status(&mut s.svm, &s.channel, STATUS_SEALED);

    // `clock.slot == open_slot + OPEN_SLOT_WINDOW` is still inside the
    // window — the reclaim gate is strict (`>`). The SEALED distribute
    // runs anyway: token movement is never slot-gated, so the refund and
    // residue sweep pay out now and the escrow ATA closes. Only the PDA
    // deallocation is deferred: the channel is left `Distributed`, holding
    // exactly its own rent, keeping the address occupied for as long as its
    // `open_slot` — a PDA seed — would still clear the open window, so the
    // same address can never be re-created.
    s.svm.warp_to_slot(open_slot + OPEN_SLOT_WINDOW);
    let channel_rent = s.svm.get_account(&s.channel).unwrap().lamports;
    s.send(s.distribute_ix())
        .expect("sealed distribute inside the window ok");
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert!(
        s.svm
            .get_account(&s.channel_ata)
            .is_none_or(|a| a.lamports == 0 && a.data.is_empty()),
        "escrow ATA closed"
    );
    read_channel(&s.svm, &s.channel, |ch| {
        assert_eq!(ch.status, STATUS_DISTRIBUTED);
    });
    assert_eq!(
        s.svm.get_account(&s.channel).unwrap().lamports,
        channel_rent
    );

    // The rent is freed by `reclaim`, gated at the same strict boundary:
    // at `open_slot + OPEN_SLOT_WINDOW` it is still too early...
    expect_custom_err(
        s.send(build_reclaim_ix(&s.channel, &s.payer)),
        PaymentChannelsError::ChannelCloseTooEarly,
    );

    // ...one slot past the window the address is surrendered.
    s.svm.warp_to_slot(open_slot + OPEN_SLOT_WINDOW + 1);
    s.send(build_reclaim_ix(&s.channel, &s.payer))
        .expect("reclaim past the close gate ok");
    assert_fully_closed(&s.svm, &s.channel);
}

#[test]
fn full_close_recovers_prefund_surplus_lamports() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_SEALED);

    // Surplus lamports parked on the live PDA (donated between open and
    // close). Full closure drains *every* lamport to the rent payer, not
    // just the rent-exempt minimum — nothing is stranded on the address.
    let surplus: u64 = 3_456_789;
    s.svm
        .airdrop(&s.channel, surplus)
        .expect("donate surplus to channel PDA");

    let payer_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;
    assert!(channel_lamports_before > surplus, "donation landed");

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_fully_closed(&s.svm, &s.channel);
    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    assert_eq!(
        payer_after - payer_before,
        channel_lamports_before + channel_ata_lamports_before,
        "rent payer recovers rent + surplus + escrow-ATA rent"
    );
}
