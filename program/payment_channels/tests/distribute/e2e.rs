//! End-to-end LiteSVM scenarios for `distribute`.
//!
//! Drives the full open → optional `settle` → distribute pipeline against
//! the compiled `.so`.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels::VOUCHER_PAYLOAD_SIZE;
use payment_channels::ed25519;
use payment_channels::instructions::distribute::DISCRIMINATOR;
use payment_channels::instructions::open::DISCRIMINATOR as OPEN_DISCRIMINATOR;
use payment_channels_client::instructions::{Settle, SettleInstructionArgs, WithdrawPayer};
use payment_channels_client::types::{DistributionRecipients, SettleArgs, VoucherArgs};
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

use super::{
    MAX_DISTRIBUTION_RECIPIENTS, STATUS_CLOSING, STATUS_FINALIZED, STATUS_OPEN, Split, TOKEN_2022,
    build_distribute_ix, build_recipients, treasury_owner,
};
use crate::common::token_2022::{
    EXT_CPI_GUARD, EXT_GROUP_MEMBER_POINTER, EXT_GROUP_POINTER, EXT_MEMO_TRANSFER,
    EXT_METADATA_POINTER, EXT_MINT_CLOSE_AUTHORITY, EXT_TOKEN_GROUP, EXT_TOKEN_GROUP_MEMBER,
    EXT_TOKEN_METADATA, EXT_TRANSFER_FEE_CONFIG, EXT_TRANSFER_HOOK, POINTER_EXTENSION_LEN,
    TOKEN_GROUP_LEN, TOKEN_GROUP_MEMBER_LEN, TOKEN_METADATA_MIN_LEN, add_account_extension,
    add_mint_extension,
};
use crate::common::{
    ATA_PROGRAM, INSTRUCTIONS_SYSVAR, PROGRAM_ID, ProgramLoader, SPL_TOKEN, SYSTEM_PROGRAM,
    SYSVAR_RENT, compute_budget_ix, ed25519_program_id, event_authority, expect_custom_err,
    expect_instruction_err, set_clock, token_balance,
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

fn read_paid_out(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    let acct = svm.get_account(channel).expect("channel exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[28..36]);
    u64::from_le_bytes(buf)
}

/// Rent-exempt lamports for the 1-byte tombstone, computed via the same
/// canonical formula `Rent::try_minimum_balance` runs on-chain.
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
// Direct byte writes to `Channel.status` / `paid_out` / `payer_withdrawn_at`.

fn mutate_channel<F: FnOnce(&mut Vec<u8>)>(svm: &mut LiteSVM, channel: &Pubkey, f: F) {
    let mut acct = svm.get_account(channel).expect("channel exists");
    f(&mut acct.data);
    svm.set_account(*channel, acct).expect("overwrite channel");
}

fn set_status(svm: &mut LiteSVM, channel: &Pubkey, status: u8) {
    mutate_channel(svm, channel, |data| data[3] = status);
}

fn set_paid_out(svm: &mut LiteSVM, channel: &Pubkey, paid_out: u64) {
    mutate_channel(svm, channel, |data| {
        data[28..36].copy_from_slice(&paid_out.to_le_bytes());
    });
}

fn set_payer_withdrawn_at(svm: &mut LiteSVM, channel: &Pubkey, ts: i64) {
    mutate_channel(svm, channel, |data| {
        data[44..52].copy_from_slice(&ts.to_le_bytes());
    });
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

fn voucher_payload(voucher: &VoucherArgs) -> [u8; VOUCHER_PAYLOAD_SIZE] {
    borsh::to_vec(voucher)
        .expect("voucher borsh encoding")
        .try_into()
        .expect("voucher payload matches VOUCHER_PAYLOAD_SIZE")
}

fn build_ed25519_ix(
    pubkey: &[u8; ed25519::PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; ed25519::SIGNATURE_SERIALIZED_SIZE],
    message: &[u8; VOUCHER_PAYLOAD_SIZE],
) -> Instruction {
    let mut data = Vec::with_capacity(ed25519::MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE);
    data.push(1u8);
    data.push(0u8);

    let pubkey_offset = ed25519::PUBKEY_OFFSET as u16;
    let signature_offset = ed25519::SIGNATURE_OFFSET as u16;
    let message_offset = ed25519::MESSAGE_OFFSET as u16;
    let message_size = VOUCHER_PAYLOAD_SIZE as u16;

    data.extend_from_slice(&signature_offset.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&pubkey_offset.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&message_offset.to_le_bytes());
    data.extend_from_slice(&message_size.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());

    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: ed25519_program_id(),
        accounts: Vec::new(),
        data,
    }
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
// needs. `status`, `paid_out`, and `payer_withdrawn_at` are mutated through
// the byte-level mutators above pending real `request_close` / `finalize` /
// `withdraw_payer` instructions.

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
    fn build(splits: Vec<Split>, deposit: u64, settled: u64, paid_out: u64, status: u8) -> Self {
        Self::build_with_token_program(splits, deposit, settled, paid_out, status, TOKEN_2022)
    }

    fn build_with_token_program(
        splits: Vec<Split>,
        deposit: u64,
        settled: u64,
        paid_out: u64,
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

        if paid_out > 0 {
            set_paid_out(&mut svm, &channel, paid_out);
        }

        if status != STATUS_OPEN {
            set_status(&mut svm, &channel, status);
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

    fn recipients(&self) -> DistributionRecipients {
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
        let blockhash = self.svm.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[compute_budget_ix(1_400_000), ix],
            Some(&self.fee_payer.pubkey()),
            &[&self.fee_payer],
            blockhash,
        );
        self.svm.send_transaction(tx)
    }
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
    let paid_out = 0;
    let mut s = Scenario::build(splits.clone(), deposit, settled, paid_out, STATUS_OPEN);

    let pool_amount = settled - paid_out;
    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 30_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[2]), 10_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 20_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), paid_out + pool_amount);
}

#[test]
fn open_flooring_residual_stays_in_channel_ata() {
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 33);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 33);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 33);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.channel_ata), 101);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
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
    let paid_out = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        paid_out,
        STATUS_OPEN,
        SPL_TOKEN,
    );

    s.send(s.distribute_ix()).expect("spl distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}

#[test]
fn happy_path_finalized_tombstone() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let deposit = 200_000;
    let settled = 150_000;
    let paid_out = 0;
    let mut s = Scenario::build(splits.clone(), deposit, settled, paid_out, STATUS_FINALIZED);

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
    let paid_out = 0;
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        paid_out,
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
    let paid_out = 100_000;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_FINALIZED);

    set_token_balance(&mut s.svm, &s.channel_ata, deposit - settled);

    s.send(s.distribute_ix()).expect("finalized zero pool ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_tombstone(&s.svm, &s.channel);
}

#[test]
fn finalized_sweeps_accumulated_flooring_residual_to_treasury() {
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
    let paid_out = 100;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_FINALIZED);

    set_token_balance(&mut s.svm, &s.channel_ata, deposit - paid_out + 1);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 16);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 16);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 16);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 3);
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_FINALIZED);

    set_payer_withdrawn_at(&mut s.svm, &s.channel, 1_700_000_000);
    set_token_balance(&mut s.svm, &s.channel_ata, settled - paid_out);

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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    let mut acct = s.svm.get_account(&s.channel).unwrap();
    acct.data[56] ^= 0xFF;
    s.svm
        .set_account(s.channel, acct)
        .expect("overwrite channel");
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
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
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
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
        let paid_out = 0;
        let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
        let paid_out_before = read_paid_out(&s.svm, &s.channel);
        add_mint_extension(&mut s.svm, &s.mint, extension_type, value_len);

        let res = s.send(s.distribute_ix());

        expect_custom_err(res, PaymentChannelsError::UnsupportedTokenExtensions);
        assert_eq!(read_paid_out(&s.svm, &s.channel), paid_out_before);
        assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
        assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    }
}

#[test]
fn unsupported_token_2022_account_extensions_reject_without_state_changes() {
    for extension_type in [EXT_MEMO_TRANSFER, EXT_CPI_GUARD] {
        let splits = vec![Split {
            owner: Pubkey::new_unique(),
            bps: 5000,
        }];
        let deposit = 200_000;
        let settled = 100_000;
        let paid_out = 0;
        let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
        let paid_out_before = read_paid_out(&s.svm, &s.channel);
        add_account_extension(&mut s.svm, &s.recipient_atas[0], extension_type, 1);

        let res = s.send(s.distribute_ix());

        expect_custom_err(res, PaymentChannelsError::UnsupportedTokenExtensions);
        assert_eq!(read_paid_out(&s.svm, &s.channel), paid_out_before);
        assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
        assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    }
}

#[test]
fn num_recipients_zero_pays_full_pool_to_payee() {
    let deposit = 200_000;
    let settled = 100_000;
    let paid_out = 0;
    let mut s = Scenario::build(vec![], deposit, settled, paid_out, STATUS_OPEN);

    let pool_amount = settled - paid_out;
    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.payee_ata), pool_amount);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), pool_amount);
}

#[test]
fn wrong_recipient_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
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
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidRecipientAccount);
}

#[test]
fn wrong_treasury_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
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
    expect_custom_err(s.send(ix), PaymentChannelsError::TreasuryAddressMismatch);
}

#[test]
fn wrong_token_program() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
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
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidTokenProgram);
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_CLOSING);
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    // Manually encode instruction data with count=33. The count>32 check
    // happens before account validation, so we can pass 0 recipient accounts.
    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&33u32.to_le_bytes());
    for _ in 0..33 {
        data.extend_from_slice(&[0u8; 32]); // recipient
        data.extend_from_slice(&1000u16.to_le_bytes()); // bps
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 60_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}

#[test]
fn bps_sum_equals_10000_still_validates_payee_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 10_000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
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
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidPayeeTokenAccount);
}

#[test]
fn wrong_payee_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let deposit = 200_000;
    let settled = 100_000;
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
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
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidPayeeTokenAccount);
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(s.recipient_atas.len(), N);
    let unique: std::collections::HashSet<_> = s.recipient_atas.iter().collect();
    assert_eq!(unique.len(), N);
    for ata in &s.recipient_atas {
        assert_eq!(token_balance(&s.svm, ata), 100);
    }
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
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
    let paid_out = 0;
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_FINALIZED);
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
    let paid_out = 0;
    let mut s = Scenario::build(splits.clone(), deposit, settled, paid_out, STATUS_FINALIZED);

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
        &[compute_budget_ix(1_400_000), distribute_ix, open_ix],
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
    let acct = s.svm.get_account(&s.channel).expect("channel exists");
    assert_eq!(
        acct.data.len(),
        216,
        "channel data restored to live size after revert",
    );
    assert_eq!(
        acct.data[0], 1,
        "discriminator restored to Channel after revert",
    );
    assert_eq!(
        acct.data[3], STATUS_FINALIZED,
        "status restored after revert",
    );
}
