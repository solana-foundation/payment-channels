//! Setup helpers for benchmark scenarios.
//!
//! Every keypair, pubkey, and mint address used by a scenario is derived
//! deterministically from a per-scenario seed string via blake3 → 32 bytes
//! → `Keypair::new_from_array` / `Pubkey::new_from_array`. This pins the
//! channel PDA bump and every recipient ATA bump across runs, eliminating
//! the dominant source of run-to-run CU variance.
//!
//! For non-OPEN prerequisite states, [`set_status`] / [`set_closure_started_at`] /
//! [`force_settled`] write the channel buffer directly — running the real
//! `request_close`/`finalize`/`settle` chain would inflate the focal tx's
//! CU measurement through unrelated setup cost.
//!
//! Voucher / precompile helpers live in [`crate::common::voucher`] and are
//! re-used across the e2e suites.

// Bench scenarios mix-and-match helpers per parameter sweep; some functions
// are only reachable from a subset of scenarios, which would otherwise
// trip `cargo test`'s dead-code warning on focused runs.
#![allow(dead_code)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, MintTo};
use payment_channels_client::instructions::{
    Open, OpenInstructionArgs, Settle, SettleInstructionArgs,
};
use payment_channels_client::types::{DistributionEntry, OpenArgs, SettleArgs, VoucherArgs};
use solana_account::Account;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{
    ATA_PROGRAM, INSTRUCTIONS_SYSVAR, PROGRAM_ID, SYSTEM_PROGRAM, SYSVAR_RENT, event_authority,
    treasury_owner,
    voucher::{build_ed25519_ix, voucher_payload},
};

pub const GRACE_PERIOD: u32 = 3_600;
pub const DEFAULT_SALT: u64 = 0x1234_5678_9abc_def0;
pub const DEFAULT_DEPOSIT: u64 = 1_000_000;
pub const DEFAULT_SETTLED: u64 = 500_000;

pub mod status {
    pub const OPEN: u8 = 0;
    pub const FINALIZED: u8 = 1;
    pub const CLOSING: u8 = 2;
}

// ---------------------------------------------------------------------------
// Seeded key derivation. Every keypair/pubkey/mint used in the bench fans
// out from `blake3(SEED_NAMESPACE || role)` — a single global seed shared
// across every scenario. Each scenario has its own LiteSVM, so identical
// addresses across scenarios don't collide; sharing them is a feature
// because it pins the base-account bumps and makes cross-row comparisons
// reflect on-chain behavior rather than bump roulette. No OsRng anywhere
// on the setup path.

const SEED_NAMESPACE: &[u8] = b"payment_channels/bench/v1/";

fn seeded_bytes(role: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEED_NAMESPACE);
    hasher.update(role.as_bytes());
    *hasher.finalize().as_bytes()
}

fn seeded_keypair(role: &str) -> Keypair {
    Keypair::new_from_array(seeded_bytes(role))
}

fn seeded_pubkey(role: &str) -> Pubkey {
    Pubkey::new_from_array(seeded_bytes(role))
}

/// Inject a fully-initialized Mint account at `mint` owned by `token_program`.
/// Replaces `litesvm_token::CreateMint::send()`, which hardcodes
/// `Keypair::new()` for the mint and so produces a different mint pubkey
/// every run — propagating bump variance into every ATA derived from
/// `(channel, token_program, mint)`. Layout is the SPL/Token-2022 base Mint
/// (82 bytes, no extensions), accepted by both programs identically.
fn inject_mint(svm: &mut LiteSVM, mint: &Pubkey, authority: &Pubkey, token_program: &Pubkey) {
    //   0..4   mint_authority_option: u32 LE (1 = Some)
    //   4..36  mint_authority: [u8; 32]
    //  36..44  supply: u64 LE  (left at 0; MintTo updates it)
    //      44  decimals: u8    (0)
    //      45  is_initialized: u8 (1)
    //  46..50  freeze_authority_option: u32 LE (0 = None)
    //  50..82  freeze_authority: [u8; 32]
    let mut data = vec![0u8; 82];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..36].copy_from_slice(authority.as_ref());
    data[45] = 1;
    svm.set_account(
        *mint,
        Account {
            lamports: Rent::default().minimum_balance(82),
            data,
            owner: *token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("inject mint");
}

/// All the state a benchmark scenario needs to talk to a single channel.
/// `payee` is a `Keypair` rather than a bare `Pubkey` because
/// `settle_and_finalize` requires the merchant (= payee) to sign; other
/// scenarios use only `payee.pubkey()`.
pub struct Fixture {
    pub payer: Keypair,
    pub payee: Keypair,
    pub authorized_signer: Keypair,
    pub mint: Pubkey,
    pub payer_ata: Pubkey,
    pub channel: Pubkey,
    pub channel_ata: Pubkey,
    pub token_program: Pubkey,
    /// `(recipient_owner, bps)` exactly as committed to the channel's
    /// distribution_hash at open. Re-presented at distribute.
    pub splits: Vec<(Pubkey, u16)>,
}

/// Deterministic (payer, mint, payer_ata). `payer` is airdropped, the mint
/// is injected at a seed-derived address, and the payer ATA is created +
/// funded with `deposit` tokens.
fn seeded_mint_funded(
    svm: &mut LiteSVM,
    deposit: u64,
    token_program: &Pubkey,
) -> (Keypair, Pubkey, Pubkey) {
    let payer = seeded_keypair("payer");
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let mint = seeded_pubkey("mint");
    inject_mint(svm, &mint, &payer.pubkey(), token_program);
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

fn derive_channel_pdas(
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
    let (channel_ata, _) = Pubkey::find_program_address(
        &[channel.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );
    (channel, channel_ata)
}

/// `n` deterministic 1-bps recipients. Sum ≤ 32 bps → payee gets 9968+ as
/// the implicit share; the distribution math stays non-trivial while
/// staying well under the 10_000 cap. The first `n` recipients are stable
/// across scenarios (e.g. `distribute[n=04]` reuses `distribute[n=01]`'s
/// recipient as its first entry), so smaller-`n` rows are a prefix of
/// larger-`n` rows in pubkey terms.
fn seeded_splits(n: usize) -> Vec<(Pubkey, u16)> {
    (0..n)
        .map(|i| {
            let role = format!("recipient/{i:02}");
            (seeded_pubkey(&role), 1u16)
        })
        .collect()
}

/// Fresh fixture with deterministic keypairs, mint, and recipient owners.
/// Every address is derived once and shared across all scenarios — each
/// scenario has its own LiteSVM, so identical addresses don't collide and
/// the shared base ensures per-row CU differences come from instruction
/// behavior, not bump roulette.
///
/// Does NOT run `open`. Use [`open_setup`] when `open` is *not* the focal
/// ix; otherwise call [`build_open_ix`] and record the resulting tx.
pub fn prepare_channel(svm: &mut LiteSVM, num_recipients: usize, token_program: Pubkey) -> Fixture {
    let (payer, mint, payer_ata) = seeded_mint_funded(svm, DEFAULT_DEPOSIT, &token_program);
    let payee = seeded_keypair("payee");
    let authorized_signer = seeded_keypair("authorized_signer");
    let (channel, channel_ata) = derive_channel_pdas(
        &payer.pubkey(),
        &payee.pubkey(),
        &mint,
        &authorized_signer.pubkey(),
        DEFAULT_SALT,
        &token_program,
    );
    let splits = seeded_splits(num_recipients);
    Fixture {
        payer,
        payee,
        authorized_signer,
        mint,
        payer_ata,
        channel,
        channel_ata,
        token_program,
        splits,
    }
}

/// Build the `open` ix from the fixture (no tx assembly, no send).
pub fn build_open_ix(f: &Fixture, deposit: u64) -> Instruction {
    let recipients: Vec<DistributionEntry> = f
        .splits
        .iter()
        .map(|(owner, bps)| DistributionEntry {
            recipient: *owner,
            bps: *bps,
        })
        .collect();
    Open {
        payer: f.payer.pubkey(),
        payee: f.payee.pubkey(),
        mint: f.mint,
        authorized_signer: f.authorized_signer.pubkey(),
        channel: f.channel,
        payer_token_account: f.payer_ata,
        channel_token_account: f.channel_ata,
        token_program: f.token_program,
        system_program: SYSTEM_PROGRAM,
        rent: SYSVAR_RENT,
        associated_token_program: ATA_PROGRAM,
        event_authority: event_authority(),
        self_program: PROGRAM_ID,
    }
    .instruction(OpenInstructionArgs {
        open_args: OpenArgs {
            salt: DEFAULT_SALT,
            deposit,
            grace_period: GRACE_PERIOD,
            recipients,
        },
    })
}

/// Run `open` as a *setup* tx (not measured) so the channel exists with a
/// valid distribution_hash for later focal ixs.
pub fn open_setup(svm: &mut LiteSVM, f: &Fixture, deposit: u64) {
    let ix = build_open_ix(f, deposit);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&f.payer.pubkey()),
        &[&f.payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("open setup ok");
}

/// `[ed25519, settle]` against the fixture's authorized signer.
pub fn build_settle_pair(
    f: &Fixture,
    cumulative_amount: u64,
    expires_at: i64,
) -> (Instruction, Instruction) {
    let voucher = VoucherArgs {
        channel_id: f.channel,
        cumulative_amount,
        expires_at,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = f.authorized_signer.sign_message(&payload).into();
    let pubkey = f.authorized_signer.pubkey().to_bytes();
    let ed_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = Settle {
        channel: f.channel,
        instructions_sysvar: INSTRUCTIONS_SYSVAR,
    }
    .instruction(SettleInstructionArgs {
        settle_args: SettleArgs { voucher },
    });
    (ed_ix, settle_ix)
}

/// Run `[ed25519, settle]` to advance the watermark to `cumulative` as a
/// *setup* tx (not measured).
pub fn settle_setup(svm: &mut LiteSVM, f: &Fixture, cumulative: u64) {
    let (ed_ix, settle_ix) = build_settle_pair(f, cumulative, 0);
    let tx = Transaction::new_signed_with_payer(
        &[ed_ix, settle_ix],
        Some(&f.payer.pubkey()),
        &[&f.payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("settle setup ok");
}

// ---------------------------------------------------------------------------
// State mutators. Identical to the byte-level helpers in
// `tests/distribute/e2e.rs` — used to skip the multi-tx prelude needed to
// reach CLOSING / FINALIZED states so the focal ix's CU isn't polluted.

fn mutate_channel<F: FnOnce(&mut Vec<u8>)>(svm: &mut LiteSVM, channel: &Pubkey, f: F) {
    let mut acct = svm.get_account(channel).expect("channel exists");
    f(&mut acct.data);
    svm.set_account(*channel, acct).expect("overwrite channel");
}

pub fn set_status(svm: &mut LiteSVM, channel: &Pubkey, s: u8) {
    mutate_channel(svm, channel, |data| data[3] = s);
}

pub fn set_closure_started_at(svm: &mut LiteSVM, channel: &Pubkey, ts: i64) {
    mutate_channel(svm, channel, |data| {
        data[36..44].copy_from_slice(&ts.to_le_bytes());
    });
}

pub fn force_settled(svm: &mut LiteSVM, channel: &Pubkey, settled: u64) {
    mutate_channel(svm, channel, |data| {
        data[20..28].copy_from_slice(&settled.to_le_bytes());
    });
}

pub fn read_channel_balance(svm: &LiteSVM, ata: &Pubkey) -> u64 {
    let acct = svm.get_account(ata).expect("ata exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

/// Create the payee, treasury, and recipient ATAs needed to run `distribute`.
pub fn create_distribute_atas(svm: &mut LiteSVM, f: &Fixture) -> DistributeAccounts {
    svm.airdrop(&f.payee.pubkey(), 1_000_000).ok();
    let payee_ata = CreateAssociatedTokenAccount::new(svm, &f.payer, &f.mint)
        .owner(&f.payee.pubkey())
        .token_program_id(&f.token_program)
        .send()
        .expect("payee ATA");

    svm.airdrop(&treasury_owner(), 1_000_000_000).ok();
    let treasury_ata = CreateAssociatedTokenAccount::new(svm, &f.payer, &f.mint)
        .owner(&treasury_owner())
        .token_program_id(&f.token_program)
        .send()
        .expect("treasury ATA");

    let mut recipient_atas = Vec::with_capacity(f.splits.len());
    for (owner, _) in &f.splits {
        svm.airdrop(owner, 1_000_000).ok();
        let ata = CreateAssociatedTokenAccount::new(svm, &f.payer, &f.mint)
            .owner(owner)
            .token_program_id(&f.token_program)
            .send()
            .expect("recipient ATA");
        recipient_atas.push(ata);
    }
    DistributeAccounts {
        payee_ata,
        treasury_ata,
        recipient_atas,
    }
}

pub struct DistributeAccounts {
    pub payee_ata: Pubkey,
    pub treasury_ata: Pubkey,
    pub recipient_atas: Vec<Pubkey>,
}
