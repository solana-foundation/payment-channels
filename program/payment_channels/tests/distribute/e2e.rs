//! End-to-end LiteSVM scenarios for `distribute`.
//!
//! Drives the full open → optional `settle` → distribute pipeline against
//! the compiled `.so`.

#![allow(clippy::result_large_err)]

use std::str::FromStr;

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels::VOUCHER_PAYLOAD_SIZE;
use payment_channels::ed25519;
use payment_channels::event_engine::event_authority_pda;
use payment_channels::instructions::open::DISCRIMINATOR as OPEN_DISCRIMINATOR;
use payment_channels_client::instructions::{Settle, SettleInstructionArgs};
use payment_channels_client::types::{DistributionRecipients, SettleArgs, VoucherArgs};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

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
    ATA_PROGRAM, PROGRAM_ID, ProgramLoader, SPL_TOKEN, SYSTEM_PROGRAM, SYSVAR_RENT,
    expect_custom_err,
};

const GRACE_PERIOD: u32 = 3600;
const DEFAULT_SALT: u64 = 0x1234_5678_9abc_def0;

fn instructions_sysvar_id() -> Pubkey {
    Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap()
}

fn ed25519_program_id() -> Pubkey {
    Pubkey::new_from_array(*ed25519::PROGRAM_ID.as_array())
}

fn event_authority() -> Pubkey {
    Pubkey::new_from_array(*event_authority_pda::ID.as_array())
}

fn compute_budget_ix(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(0x02);
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap(),
        accounts: Vec::new(),
        data,
    }
}

fn token_balance(svm: &LiteSVM, token_account: &Pubkey) -> u64 {
    let acct = svm
        .get_account(token_account)
        .expect("token account exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[64..72]);
    u64::from_le_bytes(buf)
}

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
    data.push(splits.len() as u8);
    for i in 0..MAX_DISTRIBUTION_RECIPIENTS {
        if i < splits.len() {
            data.extend_from_slice(splits[i].owner.as_ref());
            data.extend_from_slice(&splits[i].bps.to_le_bytes());
        } else {
            data.extend_from_slice(&[0u8; 34]);
        }
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
        instructions_sysvar: instructions_sysvar_id(),
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

    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_after = s
        .svm
        .get_account(&s.channel)
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(channel_lamports_after, 0);
    assert_eq!(
        payer_after - payer_balance_before,
        channel_lamports_before + channel_ata_lamports_before
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
    assert_eq!(
        s.svm
            .get_account(&s.channel)
            .map(|a| a.lamports)
            .unwrap_or(0),
        0
    );
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
    assert_eq!(
        s.svm
            .get_account(&s.channel)
            .map(|a| a.lamports)
            .unwrap_or(0),
        0
    );
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
    assert_eq!(
        s.svm
            .get_account(&s.channel)
            .map(|a| a.lamports)
            .unwrap_or(0),
        0
    );
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
    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_after = s
        .svm
        .get_account(&s.channel)
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(channel_lamports_after, 0);
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
    let mut bad = s.recipients();
    bad.count = 33;
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &s.recipient_atas,
        bad,
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidDistributionHash);
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
