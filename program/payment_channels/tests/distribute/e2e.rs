//! End-to-end LiteSVM scenarios for `distribute`.
//!
//! Drives the full open → optional `settle` → distribute pipeline against
//! the compiled `.so`.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels::instructions::distribute::DISCRIMINATOR;
use payment_channels::instructions::open::DISCRIMINATOR as OPEN_DISCRIMINATOR;
use payment_channels_client::instructions::{Settle, SettleInstructionArgs, WithdrawPayer};
use payment_channels_client::types::{
    DistributionEntry, PayoutBeneficiary, PayoutRedirected, RedirectReason, SettleArgs, VoucherArgs,
};
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use spl_token_2022_interface::state::AccountState;

use super::{
    MAX_DISTRIBUTION_RECIPIENTS, STATUS_CLOSING, STATUS_FINALIZED, STATUS_OPEN, Split, TOKEN_2022,
    build_distribute_ix, build_recipients,
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
    SYSVAR_RENT, event_authority, expect_custom_err, expect_instruction_err, mutate_channel,
    read_channel, set_clock, token_balance, treasury_owner,
    voucher::{build_ed25519_ix, voucher_payload},
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

/// Rent-exempt lamports for the 1-byte tombstone PDA.
fn tombstone_rent_lamports() -> u64 {
    solana_rent::Rent::default().minimum_balance(1)
}

/// Assert the tombstone shape of a channel PDA after FINALIZED `distribute`:
/// program-owned, 1-byte data == `ClosedChannel` discriminator, rent-exempt.
fn assert_tombstone(svm: &LiteSVM, channel: &Pubkey) {
    let acct = svm.get_account(channel).expect("tombstone exists");
    assert_eq!(acct.owner, PROGRAM_ID, "tombstone stays program-owned");
    assert_eq!(acct.data.len(), 1, "tombstone shrinks to 1 byte");
    assert_eq!(acct.data[0], 2, "discriminator = ClosedChannel");
    assert_eq!(
        acct.lamports,
        tombstone_rent_lamports(),
        "tombstone rent-exempt at 1 byte",
    );
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

fn derive_pdas_with_token_program(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
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
    splits: &[Split],
) -> Vec<u8> {
    assert!(splits.len() <= MAX_DISTRIBUTION_RECIPIENTS);
    let mut data = vec![OPEN_DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&grace_period.to_le_bytes());
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
    splits: &[Split],
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &open_ix_data_for_splits(salt, deposit, grace_period, splits),
        vec![
            AccountMeta::new(*payer, true),
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
    let (channel, channel_ata) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        mint,
        &authorized_signer.pubkey(),
        salt,
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

fn build_settle_ix(channel: &Pubkey, voucher: VoucherArgs) -> Instruction {
    Settle {
        channel: *channel,
        instructions_sysvar: INSTRUCTIONS_SYSVAR,
    }
    .instruction(SettleInstructionArgs {
        settle_args: SettleArgs { voucher },
    })
}

fn settle_to(
    svm: &mut LiteSVM,
    fee_payer: &Keypair,
    channel: &Pubkey,
    authorized_signer: &Keypair,
    cumulative_amount: u64,
    expires_at: i64,
) {
    let voucher = VoucherArgs {
        channel_id: *channel,
        cumulative_amount,
        expires_at,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();
    let pubkey = authorized_signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(channel, voucher);

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
// `request_close` / `finalize` / `withdraw_payer` instructions.
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
fn finalized_after_open_zero_delta_distribution_refunds_and_sweeps_residual() {
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

    set_status(&mut s.svm, &s.channel, STATUS_FINALIZED);
    s.send(s.distribute_ix())
        .expect("finalized zero-delta close ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), settled);
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn finalized_after_withdraw_payer_sweeps_open_zero_delta_residual_once() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 10;
    let settled = 1;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_OPEN);

    s.send(s.distribute_ix())
        .expect("open zero-delta distribution ok");
    set_status(&mut s.svm, &s.channel, STATUS_FINALIZED);

    set_clock(&mut s.svm, 1_000_000);
    send_withdraw_payer(&mut s);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);

    s.send(s.distribute_ix())
        .expect("finalized residual sweep after withdraw ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), settled);
    assert_tombstone(&s.svm, &s.channel);
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

    set_status(&mut s.svm, &s.channel, STATUS_FINALIZED);
    s.send(s.distribute_ix()).expect("finalized distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 50);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_tombstone(&s.svm, &s.channel);
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

    set_status(&mut s.svm, &s.channel, STATUS_FINALIZED);
    s.send(s.distribute_ix()).expect("finalized distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 1);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 1);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 2);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 2);
    assert_tombstone(&s.svm, &s.channel);
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
fn happy_path_finalized_tombstone() {
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
        STATUS_FINALIZED,
    );

    let payer_balance_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);

    assert_tombstone(&s.svm, &s.channel);

    // Payer recovers the channel rent delta plus the full escrow ATA rent.
    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_rent_delta = channel_lamports_before - tombstone_rent_lamports();
    assert_eq!(
        payer_after - payer_balance_before,
        channel_rent_delta + channel_ata_lamports_before
    );
}

#[test]
fn happy_path_finalized_tombstone_spl_token() {
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
        STATUS_FINALIZED,
        SPL_TOKEN,
    );

    s.send(s.distribute_ix()).expect("spl finalized ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn distribute_after_withdraw_payer_skips_payer_refund() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        0,
        STATUS_FINALIZED,
        SPL_TOKEN,
    );

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
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn finalized_zero_pool_still_refunds_and_tombstones() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 100_000;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_FINALIZED);

    set_token_balance(&mut s.svm, &s.channel_ata, deposit - settled);

    s.send(s.distribute_ix()).expect("finalized zero pool ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn finalized_sweeps_final_flooring_residual_to_treasury() {
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
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_FINALIZED);

    set_token_balance(&mut s.svm, &s.channel_ata, deposit - payout_watermark + 1);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 16);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 16);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 17);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 2);
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn happy_path_finalized_already_withdrawn() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_FINALIZED);

    set_payer_withdrawn_at(&mut s.svm, &s.channel, 1_700_000_000);
    set_token_balance(&mut s.svm, &s.channel_ata, settled - payout_watermark);

    let payer_balance_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_tombstone(&s.svm, &s.channel);

    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_rent_delta = channel_lamports_before - tombstone_rent_lamports();
    assert_eq!(
        payer_after - payer_balance_before,
        channel_rent_delta + channel_ata_lamports_before
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

// A poisoned recipient must not block the finalized tombstone. The
// reassigned-owner share forfeits to treasury and the channel closes, draining
// the escrow and tombstoning the PDA.
#[test]
fn reassigned_recipient_ata_owner_redirects_and_tombstones_in_finalized() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_FINALIZED);
    let poisoned_owner = s.splits[0].owner;
    set_token_account_owner(&mut s.svm, &s.recipient_atas[0], &Pubkey::new_unique());

    let meta = s
        .send(s.distribute_ix())
        .expect("reassigned recipient ATA owner forfeits its share; tombstone completes");

    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 75_000);
    assert_tombstone(&s.svm, &s.channel);

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
// `SetAuthority(AccountOwner)` must not be able to brick the finalized close.
// The refund forfeits to treasury (`ReassignedAuthority`) and the channel
// tombstones; the recipient and payee legs are paid normally.
#[test]
fn reassigned_payer_ata_owner_redirects_refund_to_treasury_in_finalized() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_FINALIZED);
    set_token_account_owner(&mut s.svm, &s.payer_ata, &Pubkey::new_unique());

    let meta = s
        .send(s.distribute_ix())
        .expect("reassigned payer ATA owner forfeits refund; tombstone completes");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), deposit - settled);
    assert_tombstone(&s.svm, &s.channel);

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
fn frozen_payer_ata_redirects_refund_to_treasury_in_finalized() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let mut s = Scenario::build(splits, deposit, settled, 0, STATUS_FINALIZED);
    set_token_account_state(&mut s.svm, &s.payer_ata, AccountState::Frozen);

    let meta = s
        .send(s.distribute_ix())
        .expect("frozen payer ATA forfeits refund; tombstone completes");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), deposit - settled);
    assert_tombstone(&s.svm, &s.channel);

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
fn zero_share_poisoned_payee_does_not_block_recipient_only_finalized_distribute() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 10_000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_FINALIZED);
    add_account_extension(&mut s.svm, &s.payee_ata, EXT_MEMO_TRANSFER, 1);

    s.send(s.distribute_ix())
        .expect("zero-share poisoned payee must not block finalized close");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), settled);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_tombstone(&s.svm, &s.channel);
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
fn poisoned_payer_ata_redirects_refund_to_treasury_in_finalized_with_refund() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_FINALIZED);
    add_account_extension(&mut s.svm, &s.payer_ata, EXT_MEMO_TRANSFER, 1);

    s.send(s.distribute_ix())
        .expect("poisoned payer ATA forfeits refund; tombstone completes");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), deposit - settled);
    assert_tombstone(&s.svm, &s.channel);
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
fn happy_path_spl_token_finalized_max_recipients_plus_payee_refund_sweep() {
    // Worst-case FINALIZED distribute: every payout phase present —
    // N=32 recipients + payee + payer refund + sweep = 35 logical slots
    // across 5 chunks (8+8+8+8+3), followed by a standalone escrow-close CPI
    // in the shared tombstone tail.
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
        STATUS_FINALIZED,
        SPL_TOKEN,
    );

    let escrow_before = token_balance(&s.svm, &s.channel_ata);
    let payer_sol_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send_v0_distribute(s.recipient_atas.clone(), None)
        .expect("spl finalized max recipients ok");

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

    assert_tombstone(&s.svm, &s.channel);

    // Payer recovers channel-rent delta + escrow-ATA rent on the SOL leg.
    let payer_sol_after = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_rent_delta = channel_lamports_before - tombstone_rent_lamports();
    assert_eq!(
        payer_sol_after - payer_sol_before,
        channel_rent_delta + channel_ata_lamports_before
    );
}

#[test]
fn spl_token_finalized_zero_pool_still_refunds_and_tombstones() {
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
        STATUS_FINALIZED,
        SPL_TOKEN,
    );

    // Simulate the post-OPEN escrow balance: just the refund headroom left.
    set_token_balance(&mut s.svm, &s.channel_ata, deposit - settled);

    s.send(s.distribute_ix())
        .expect("spl finalized zero pool ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn spl_token_finalized_already_withdrawn() {
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
        STATUS_FINALIZED,
        SPL_TOKEN,
    );

    // Simulate post-`withdraw_payer` state: stamp + trim escrow accordingly.
    mutate_channel(&mut s.svm, &s.channel, |ch| {
        ch.set_payer_withdrawn_at(1_700_000_000)
    });
    set_token_balance(&mut s.svm, &s.channel_ata, settled - payout_watermark);

    s.send(s.distribute_ix())
        .expect("spl finalized already-withdrawn ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn spl_token_finalized_chunk_boundary() {
    // N=7 recipients + payee = 8 exactly fills one chunk; the FINALIZED
    // tail (refund + sweep) spills into a second chunk of 2, followed by a
    // standalone escrow-close CPI in the shared tombstone tail.
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
        STATUS_FINALIZED,
        SPL_TOKEN,
    );

    let escrow_before = token_balance(&s.svm, &s.channel_ata);
    let payer_sol_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix())
        .expect("spl finalized chunk-boundary ok");

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
    assert_tombstone(&s.svm, &s.channel);

    let payer_sol_after = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_rent_delta = channel_lamports_before - tombstone_rent_lamports();
    assert_eq!(
        payer_sol_after - payer_sol_before,
        channel_rent_delta + channel_ata_lamports_before
    );
}

#[test]
fn token_2022_max_recipients_plus_payee_finalized() {
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
        STATUS_FINALIZED,
        TOKEN_2022,
    );

    let escrow_before = token_balance(&s.svm, &s.channel_ata);
    // Token-2022 FINALIZED at N=32 needs to increase compute budget limit; default CU cap (200k) is too low.
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
    assert_tombstone(&s.svm, &s.channel);
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
// LiteSVM-only tombstone tests. Mollusk variants for `distribute` / `top_up`
// rejection on a tombstoned channel live in their respective `integration.rs`
// suites; these scenarios exercise behavior that needs a real SVM:
//   - the Ed25519 precompile + `Instructions` sysvar (settle),
//   - the system program's `CreateAccount` rejection path through `open`'s
//     CPI chain (across-tx reopen),
//   - and end-of-tx rollback semantics (same-tx reopen).

/// Drive a Scenario to FINALIZED with one 50/50 split, then run distribute
/// to produce the tombstone. Returns the now-tombstoned scenario.
fn finalized_then_tombstoned() -> Scenario {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let payout_watermark = 0;
    let mut s = Scenario::build(splits, deposit, settled, payout_watermark, STATUS_FINALIZED);
    s.send(s.distribute_ix()).expect("distribute ok");
    assert_tombstone(&s.svm, &s.channel);
    s
}

#[test]
fn settle_on_tombstoned_channel_rejects() {
    let mut s = finalized_then_tombstoned();

    // A voucher that would be valid against a fresh channel at these seeds:
    // strictly monotonic cumulative_amount, no expiry. `Channel::load_mut`
    // length-gates the 1-byte tombstone buffer before any voucher logic runs.
    let voucher = VoucherArgs {
        channel_id: s.channel,
        cumulative_amount: 1,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = s.authorized_signer.sign_message(&payload).into();
    let pubkey = s.authorized_signer.pubkey().to_bytes();
    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&s.channel, voucher);

    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&s.fee_payer.pubkey()),
        &[&s.fee_payer],
        blockhash,
    );
    expect_instruction_err(
        s.svm.send_transaction(tx),
        InstructionError::InvalidAccountData,
    );
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn reopen_at_same_seeds_rejects_across_tx() {
    let mut s = finalized_then_tombstoned();

    // Attempt a fresh `open` on the same (payer, payee, mint, signer, salt)
    // tuple in a new transaction. The system program's `CreateAccount`
    // rejects because the PDA is non-empty + program-owned, surfacing as
    // `SystemError::AccountAlreadyInUse` (= 0) propagated through `open`'s
    // CPI as `InstructionError::Custom(0)`.
    let open_ix = open_ix_for_splits(
        &s.payer,
        &s.payee,
        &s.mint,
        &s.authorized_signer.pubkey(),
        &s.channel,
        &s.payer_ata,
        &s.channel_ata,
        &s.token_program,
        DEFAULT_SALT,
        1, // tiny deposit; ix fails before this matters
        GRACE_PERIOD,
        &s.splits,
    );

    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[open_ix],
        Some(&s.payer_keypair.pubkey()),
        &[&s.payer_keypair],
        blockhash,
    );
    expect_instruction_err(s.svm.send_transaction(tx), InstructionError::Custom(0));
    // Tombstone bytes preserved — no partial reinit happened.
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn reopen_at_same_seeds_rejects_same_tx() {
    // Bundle distribute + open in a single tx. distribute would tombstone
    // the channel mid-tx; open with identical seeds must still fail before
    // commit, otherwise the runtime's tx-rollback is the only thing
    // protecting against in-tx voucher replay against a fresh channel.
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
        STATUS_FINALIZED,
    );

    let distribute_ix = s.distribute_ix();
    let open_ix = open_ix_for_splits(
        &s.payer,
        &s.payee,
        &s.mint,
        &s.authorized_signer.pubkey(),
        &s.channel,
        &s.payer_ata,
        &s.channel_ata,
        &s.token_program,
        DEFAULT_SALT,
        1,
        GRACE_PERIOD,
        &splits,
    );

    let blockhash = s.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(MAX_COMPUTE_UNIT_LIMIT),
            distribute_ix,
            open_ix,
        ],
        Some(&s.payer_keypair.pubkey()),
        &[&s.payer_keypair],
        blockhash,
    );
    let err = s.svm.send_transaction(tx).expect_err("tx should fail").err;
    // Lock down both the failing ix index (open is at index 2 — after
    // compute-budget at 0 and distribute at 1) and the variant. A regression
    // that shifts the failure to a different ix or a different system error
    // would mask the in-tx replay protection this test asserts.
    match err {
        TransactionError::InstructionError(2, InstructionError::Custom(0)) => {}
        other => panic!(
            "expected open ix (index 2) to fail with SystemError::AccountAlreadyInUse, got {other:?}"
        ),
    }

    // Tx reverted: channel is restored to its pre-tx FINALIZED state.
    read_channel(&s.svm, &s.channel, |ch| {
        assert_eq!(
            ch.discriminator, 1,
            "discriminator restored to Channel after revert",
        );
        assert_eq!(ch.status, STATUS_FINALIZED, "status restored after revert");
    });
}
