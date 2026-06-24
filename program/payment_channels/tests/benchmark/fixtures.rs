//! Setup helpers for benchmark scenarios.
//!
//! Every keypair, pubkey, and mint address used by a scenario is derived
//! deterministically from a per-scenario seed string via blake3 → 32 bytes
//! → `Keypair::new_from_array` / `Pubkey::new_from_array`. This pins the
//! channel PDA bump and every recipient ATA bump across runs, eliminating
//! the dominant source of run-to-run CU variance.
//!
//! For non-OPEN prerequisite states, scenarios use `mutate_channel` (in
//! [`crate::common`]) to write the channel buffer directly — running the real
//! `request_close`/`finalize`/`settle` chain would inflate the focal tx's
//! CU measurement through unrelated setup cost.
//!
//! Voucher / precompile helpers live in [`crate::common::voucher`] and are
//! re-used across the e2e suites.

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, MintTo};
use payment_channels_client::instructions::{Open, OpenInstructionArgs, Settle};
use payment_channels_client::types::{DistributionEntry, OpenArgs, VoucherArgs};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::create_account;
use solana_transaction::Transaction;
use spl_token_2022_interface::instruction::initialize_mint2;

use crate::common::{
    ATA_PROGRAM, INSTRUCTIONS_SYSVAR, PROGRAM_ID, SYSTEM_PROGRAM, SYSVAR_RENT, event_authority,
    treasury_owner,
    voucher::{build_ed25519_ix, voucher_payload},
};

pub const GRACE_PERIOD: u32 = 3_600;
pub const DEFAULT_SALT: u64 = 0x1234_5678_9abc_def0;
pub const DEFAULT_DEPOSIT: u64 = 1_000_000;
pub const DEFAULT_SETTLED: u64 = 500_000;

/// `Channel.status` byte values mirroring the on-chain `ChannelStatus`
/// repr; kept as explicit `u8`s so the bench's byte-level mutators stay
/// independent of the generated client and would surface any layout drift
/// from the program enum. `OPEN` is only referenced symbolically (channels
/// start in this state and no scenario writes it back), hence the targeted
/// `#[allow(dead_code)]`.
pub mod status {
    #[allow(dead_code)]
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

/// Create a Mint at the seeded mint keypair, owned by `token_program`.
///
/// Mirrors `litesvm_token::CreateMint::send()` (which would also issue
/// `create_account` + `initialize_mint2`), except the mint keypair is
/// deterministic instead of `Keypair::new()`. A stable mint pubkey is the
/// dominant lever on cross-run CU determinism because every ATA derived
/// from `(channel, token_program, mint)` would otherwise see bump roulette.
///
/// `initialize_mint2` from `spl-token-2022-interface` accepts both the
/// classic SPL Token program and Token-2022 (the wire format is identical
/// at the no-extension base layout).
fn create_seeded_mint(
    svm: &mut LiteSVM,
    payer: &Keypair,
    token_program: &Pubkey,
) -> (Keypair, Pubkey) {
    let mint_kp = seeded_keypair("mint");
    let mint_pk = mint_kp.pubkey();
    // Base Mint layout — 82 bytes for both SPL Token and Token-2022 with
    // no extensions; matches what `litesvm_token::CreateMint` allocates
    // when its `token-2022` feature is off.
    const MINT_LEN: u64 = 82;
    let rent = svm.minimum_balance_for_rent_exemption(MINT_LEN as usize);

    let create_ix = create_account(&payer.pubkey(), &mint_pk, rent, MINT_LEN, token_program);
    let init_ix = initialize_mint2(token_program, &mint_pk, &payer.pubkey(), None, 0)
        .expect("initialize_mint2 ix");

    let tx = Transaction::new_signed_with_payer(
        &[create_ix, init_ix],
        Some(&payer.pubkey()),
        &[payer, &mint_kp],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("create mint");
    (mint_kp, mint_pk)
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
/// is created at a seed-derived keypair via the real `create_account +
/// initialize_mint2` path, and the payer ATA is created + funded with
/// `deposit` tokens.
fn seeded_mint_funded(
    svm: &mut LiteSVM,
    deposit: u64,
    token_program: &Pubkey,
) -> (Keypair, Pubkey, Pubkey) {
    let payer = seeded_keypair("payer");
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (_mint_kp, mint) = create_seeded_mint(svm, &payer, token_program);
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
    .instruction();
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

// ---------------------------------------------------------------------------
// Address Lookup Table support for scenarios that overflow the 1232-byte
// legacy transaction account-list limit (e.g. n=32 `distribute`). An ALT is
// created + extended in a setup tx, the slot is warped (ALTs are
// activation-deferred by one slot), and callers compile a `MessageV0` against
// the returned [`AddressLookupTableAccount`].

use solana_address_lookup_table_interface::instruction::{
    create_lookup_table, extend_lookup_table,
};
use solana_message::AddressLookupTableAccount;

/// Create + extend an ALT covering `addresses`, then advance the slot so
/// later v0 transactions can resolve it. Returns the
/// [`AddressLookupTableAccount`] ready to feed into
/// [`solana_message::v0::Message::try_compile`].
pub fn build_address_lookup_table(
    svm: &mut LiteSVM,
    payer: &Keypair,
    addresses: Vec<Pubkey>,
) -> AddressLookupTableAccount {
    // Slot 0 is the genesis slot under LiteSVM. `create_lookup_table` takes
    // the recent slot as its third argument; pass `0` and warp afterwards.
    let (create_ix, table_address) = create_lookup_table(payer.pubkey(), payer.pubkey(), 0);
    let extend_ix = extend_lookup_table(
        table_address,
        payer.pubkey(),
        Some(payer.pubkey()),
        addresses.clone(),
    );
    let msg = solana_message::Message::new(&[create_ix, extend_ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx).expect("alt setup ok");
    // ALTs created in slot N are only resolvable starting in slot N+1.
    svm.warp_to_slot(svm.get_sysvar::<solana_clock::Clock>().slot + 1);

    AddressLookupTableAccount {
        key: table_address,
        addresses,
    }
}
