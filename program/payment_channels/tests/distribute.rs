//! End-to-end validation of `distribute` against the compiled .so.
//!
//! We fabricate the Channel state directly (bypassing the stub `open`) because
//! `open` does not yet persist the distribution commitment or escrow balance.
//! Once `open` lands, these tests can be migrated to the canonical flow; the
//! split-config rehash, pool math, and tombstone semantics being exercised are
//! independent of how the channel got there.

#![allow(clippy::result_large_err)]

use std::str::FromStr;

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels_client::instructions::{Distribute, DistributeInstructionArgs};
use payment_channels_client::types::DistributeArgs;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

mod common;
use common::{PROGRAM_ID, expect_custom_err, load_program};

// ---------------------------------------------------------------------------
// Constants (mirroring the on-chain program — kept in sync by compile failure
// if the client types drift).

const CHANNEL_SEED: &[u8] = b"channel";
const MAX_DISTRIBUTION_RECIPIENTS: usize = 32;
const ENTRY_LEN: usize = 34;
const MAX_DISTRIBUTE_PREIMAGE: usize = 1 + MAX_DISTRIBUTION_RECIPIENTS * ENTRY_LEN;

/// Match `constants::TREASURY_OWNER` — alternating `0xBE 0xEF` × 16.
fn treasury_owner() -> Pubkey {
    let mut b = [0u8; 32];
    for i in 0..16 {
        b[i * 2] = 0xBE;
        b[i * 2 + 1] = 0xEF;
    }
    Pubkey::new_from_array(b)
}

const TOKEN_2022_ACCOUNT_TYPE_OFFSET: usize = 165;
const TOKEN_2022_TLV_START: usize = TOKEN_2022_ACCOUNT_TYPE_OFFSET + 1;
const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
const EXT_MINT_CLOSE_AUTHORITY: u16 = 3;
const EXT_IMMUTABLE_OWNER: u16 = 7;
const EXT_MEMO_TRANSFER: u16 = 8;
const EXT_CPI_GUARD: u16 = 11;
const EXT_TRANSFER_HOOK: u16 = 14;
const EXT_METADATA_POINTER: u16 = 18;
const EXT_TOKEN_METADATA: u16 = 19;
const EXT_GROUP_POINTER: u16 = 20;
const EXT_TOKEN_GROUP: u16 = 21;
const EXT_GROUP_MEMBER_POINTER: u16 = 22;
const EXT_TOKEN_GROUP_MEMBER: u16 = 23;
const POINTER_EXTENSION_LEN: usize = 64;
const TOKEN_METADATA_MIN_LEN: usize = 80;
const TOKEN_GROUP_LEN: usize = 80;
const TOKEN_GROUP_MEMBER_LEN: usize = 72;

fn token_2022_program_id() -> Pubkey {
    Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap()
}

fn spl_token_program_id() -> Pubkey {
    Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}

fn compute_budget_ix(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(2); // ComputeBudgetInstruction::SetComputeUnitLimit
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap(),
        accounts: vec![],
        data,
    }
}

// ---------------------------------------------------------------------------
// Helpers

/// Pair of `(recipient_owner, bps)` that fully specifies one split.
#[derive(Clone, Copy)]
struct Split {
    owner: Pubkey,
    bps: u16,
}

/// Channel PDA derivation mirroring `Channel::find_pda`.
fn find_channel_pda(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            CHANNEL_SEED,
            payer.as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
        ],
        &PROGRAM_ID,
    )
}

/// Build the `num_recipients(1) || entries(n × 34)` preimage.
///
/// No upper-bound assert: callers may intentionally construct oversize
/// preimages to trigger on-chain length / count validation.
fn build_preimage(splits: &[Split]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + splits.len() * ENTRY_LEN);
    out.push(splits.len() as u8);
    for s in splits {
        out.extend_from_slice(s.owner.as_ref());
        out.extend_from_slice(&s.bps.to_le_bytes());
    }
    out
}

/// Pad the active preimage prefix into the fixed MAX_DISTRIBUTE_PREIMAGE buffer.
fn preimage_buffer(active: &[u8]) -> [u8; MAX_DISTRIBUTE_PREIMAGE] {
    assert!(active.len() <= MAX_DISTRIBUTE_PREIMAGE);
    let mut buf = [0u8; MAX_DISTRIBUTE_PREIMAGE];
    buf[..active.len()].copy_from_slice(active);
    buf
}

/// Seed a Channel PDA with the fields the distribute path reads.
#[allow(clippy::too_many_arguments)]
fn seed_channel(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    bump: u8,
    status: u8,
    salt: u64,
    deposit: u64,
    settled: u64,
    paid_out: u64,
    payer_withdrawn_at: i64,
    distribution_hash: [u8; 32],
    payer: &Pubkey,
    payee: &Pubkey,
    authorized_signer: &Pubkey,
    mint: &Pubkey,
) {
    let mut data = vec![0u8; 216];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[2] = bump;
    data[3] = status;
    data[4..12].copy_from_slice(&salt.to_le_bytes());
    data[12..20].copy_from_slice(&deposit.to_le_bytes());
    data[20..28].copy_from_slice(&settled.to_le_bytes());
    data[28..36].copy_from_slice(&paid_out.to_le_bytes());
    // 36..44 closure_started_at = 0
    data[44..52].copy_from_slice(&payer_withdrawn_at.to_le_bytes());
    // 52..56 grace_period = 0
    data[56..88].copy_from_slice(&distribution_hash);
    data[88..120].copy_from_slice(payer.as_ref());
    data[120..152].copy_from_slice(payee.as_ref());
    data[152..184].copy_from_slice(authorized_signer.as_ref());
    data[184..216].copy_from_slice(mint.as_ref());

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

/// Read the `amount` field (bytes 64..72) of a classic SPL Token account.
fn token_balance(svm: &LiteSVM, token_account: &Pubkey) -> u64 {
    let acct = svm
        .get_account(token_account)
        .expect("token account exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[64..72]);
    u64::from_le_bytes(buf)
}

/// Read `paid_out` from the channel account (bytes 28..36).
fn read_paid_out(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    let acct = svm.get_account(channel).expect("channel exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[28..36]);
    u64::from_le_bytes(buf)
}

fn add_mint_extension(svm: &mut LiteSVM, mint: &Pubkey, extension_type: u16, value_len: usize) {
    let mut acct = svm.get_account(mint).expect("mint exists");
    add_token_2022_extension(
        &mut acct.data,
        82,
        TOKEN_2022_ACCOUNT_TYPE_MINT,
        extension_type,
        value_len,
    );
    svm.set_account(*mint, acct).expect("overwrite mint");
}

fn add_account_extension(
    svm: &mut LiteSVM,
    token_account: &Pubkey,
    extension_type: u16,
    value_len: usize,
) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    add_token_2022_extension(
        &mut acct.data,
        165,
        TOKEN_2022_ACCOUNT_TYPE_ACCOUNT,
        extension_type,
        value_len,
    );
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

fn add_token_2022_extension(
    data: &mut Vec<u8>,
    base_len: usize,
    account_type: u8,
    extension_type: u16,
    value_len: usize,
) {
    if data.len() < TOKEN_2022_TLV_START {
        data.resize(TOKEN_2022_TLV_START, 0);
    }
    data[base_len..TOKEN_2022_ACCOUNT_TYPE_OFFSET].fill(0);
    data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] = account_type;
    data.extend_from_slice(&extension_type.to_le_bytes());
    data.extend_from_slice(&(value_len as u16).to_le_bytes());
    data.resize(data.len() + value_len, 0);
}

/// Full distribute ix build with the 7-slot fixed head + dynamic recipient tail.
#[allow(clippy::too_many_arguments)]
fn build_distribute_ix(
    channel: &Pubkey,
    payer: &Pubkey,
    channel_ata: &Pubkey,
    payer_ata: &Pubkey,
    treasury_ata: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    recipient_atas: &[Pubkey],
    salt: u64,
    preimage_active: &[u8],
) -> Instruction {
    let args = DistributeArgs {
        salt,
        preimage_len: preimage_active.len() as u16,
        preimage: preimage_buffer(preimage_active),
    };
    let remaining: Vec<AccountMeta> = recipient_atas
        .iter()
        .map(|a| AccountMeta::new(*a, false))
        .collect();
    let base = Distribute {
        channel: *channel,
        payer: *payer,
        channel_token_account: *channel_ata,
        payer_token_account: *payer_ata,
        treasury_token_account: *treasury_ata,
        mint: *mint,
        token_program: *token_program,
    };
    base.instruction_with_remaining_accounts(
        DistributeInstructionArgs {
            distribute_args: args,
        },
        &remaining,
    )
}

/// One-stop scenario fixture: `LiteSVM` + the channel/mint/account keys needed
/// for a happy-path distribute test.
struct Scenario {
    svm: LiteSVM,
    fee_payer: Keypair,
    mint: Pubkey,
    payer: Pubkey,
    salt: u64,
    channel: Pubkey,
    channel_ata: Pubkey,
    payer_ata: Pubkey,
    treasury_ata: Pubkey,
    token_program: Pubkey,
    recipient_atas: Vec<Pubkey>,
    splits: Vec<Split>,
}

impl Scenario {
    /// Fabricate a Token-2022 scenario with the given splits + channel balances.
    fn build(splits: Vec<Split>, deposit: u64, settled: u64, paid_out: u64, status: u8) -> Self {
        Self::build_with_token_program(
            splits,
            deposit,
            settled,
            paid_out,
            status,
            token_2022_program_id(),
        )
    }

    /// Fabricate a scenario with the given splits + channel balances. Creates
    /// the mint/ATAs under `token_program`, and mints `deposit` tokens into the
    /// channel ATA.
    fn build_with_token_program(
        splits: Vec<Split>,
        deposit: u64,
        settled: u64,
        paid_out: u64,
        status: u8,
        token_program: Pubkey,
    ) -> Self {
        let mut svm = load_program();
        let fee_payer = Keypair::new();
        svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

        let payer = Pubkey::new_unique();
        let payee = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let salt: u64 = 0x1234_5678_9abc_def0;

        let mint = CreateMint::new(&mut svm, &fee_payer)
            .decimals(6)
            .token_program_id(&token_program)
            .send()
            .expect("create mint");

        let (channel, bump) = find_channel_pda(&payer, &payee, &mint, &authorized_signer, salt);

        // Fund the payer so the payer ATA can be owned by a live key — ATAs
        // don't require the owner to have lamports, but some litesvm paths
        // need the wallet account to exist. Airdropping is cheap.
        svm.airdrop(&payer, 1_000_000_000).unwrap();
        svm.airdrop(&treasury_owner(), 1_000_000_000).unwrap();

        let channel_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&channel)
            .token_program_id(&token_program)
            .send()
            .expect("channel ATA");
        let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&payer)
            .token_program_id(&token_program)
            .send()
            .expect("payer ATA");
        let treasury = treasury_owner();
        let treasury_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&treasury)
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

            // Fund each recipient wallet so ATA creation works cleanly.
            svm.airdrop(&s.owner, 1_000_000).ok();
            let r_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
                .owner(&s.owner)
                .token_program_id(&token_program)
                .send()
                .expect("recipient ATA");
            created_recipient_atas.push((s.owner, r_ata));
            recipient_atas.push(r_ata);
        }

        // Fund the channel ATA with `deposit` tokens (simulating what `open`
        // would have transferred).
        MintTo::new(&mut svm, &fee_payer, &mint, &channel_ata, deposit)
            .token_program_id(&token_program)
            .send()
            .expect("mint to channel");

        // Commit preimage hash so `distribute` accepts the preimage we'll send.
        let preimage = build_preimage(&splits);
        let hash = blake3::hash(&preimage);

        seed_channel(
            &mut svm,
            &channel,
            bump,
            status,
            salt,
            deposit,
            settled,
            paid_out,
            0,
            *hash.as_bytes(),
            &payer,
            &payee,
            &authorized_signer,
            &mint,
        );

        // `payee`, `authorized_signer`, `bump` are PDA seed inputs only; we
        // keep them as scenario fields for reconstruction but never touch them
        // post-seed.
        let _ = (payee, authorized_signer, bump);

        Self {
            svm,
            fee_payer,
            mint,
            payer,
            salt,
            channel,
            channel_ata,
            payer_ata,
            treasury_ata,
            token_program,
            recipient_atas,
            splits,
        }
    }

    /// Borsh preimage for the scenario's declared splits.
    fn preimage(&self) -> Vec<u8> {
        build_preimage(&self.splits)
    }

    fn distribute_ix(&self) -> Instruction {
        let preimage = self.preimage();
        build_distribute_ix(
            &self.channel,
            &self.payer,
            &self.channel_ata,
            &self.payer_ata,
            &self.treasury_ata,
            &self.mint,
            &self.token_program,
            &self.recipient_atas,
            self.salt,
            &preimage,
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

/// Re-order the `(deposit, settled, paid_out)` tuple at the call site so the
/// test literal reads in deposit→settled→paid_out order regardless of the
/// positional args to `Scenario::build`.
#[inline]
fn pool(deposit: u64, paid_out: u64, settled: u64) -> (u64, u64, u64) {
    (deposit, settled, paid_out)
}

// ---------------------------------------------------------------------------
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
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build(splits.clone(), deposit, settled, paid_out, 0);

    let pool_amount = settled - paid_out;
    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 30_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[2]), 10_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 20_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), paid_out + pool_amount);
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
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        paid_out,
        0,
        spl_token_program_id(),
    );

    s.send(s.distribute_ix()).expect("spl distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}

#[test]
fn happy_path_finalized_tombstone() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    // Finalized (status=1), deposit=200k, settled=150k, paid_out=0.
    // Pool = 150k. Payer ATA should receive (50% * 150k)=75k + (deposit-settled)=50k = 125k.
    let (deposit, settled, paid_out) = pool(200_000, 0, 150_000);
    let mut s = Scenario::build(splits.clone(), deposit, settled, paid_out, 1);

    let payer_balance_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix()).expect("distribute ok");

    // Recipient balance = 50% of pool.
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    // Payer implicit share (50%) + refund (deposit − settled).
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 75_000 + 50_000);
    // Treasury got nothing (exact math).
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);

    // Tombstone: channel PDA rent + channel_token_account rent both flow to
    // the payer SOL wallet. Channel account.lamports=0 after close().
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
    let (deposit, settled, paid_out) = pool(200_000, 0, 150_000);
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        paid_out,
        1,
        spl_token_program_id(),
    );

    s.send(s.distribute_ix()).expect("spl finalized ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 125_000);
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
    let (deposit, settled, paid_out) = pool(200_000, 100_000, 100_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, 1);

    // Simulate a prior OPEN distribution that already paid the whole settled
    // pool; only the payer refund remains in escrow.
    let mut channel_ata = s.svm.get_account(&s.channel_ata).unwrap();
    channel_ata.data[64..72].copy_from_slice(&(deposit - settled).to_le_bytes());
    s.svm
        .set_account(s.channel_ata, channel_ata)
        .expect("overwrite channel ATA balance");

    s.send(s.distribute_ix()).expect("finalized zero pool ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
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
    let (deposit, settled, paid_out) = pool(200_000, 0, 150_000);
    let mut svm = load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let payer = Pubkey::new_unique();
    let payee = Pubkey::new_unique();
    let _ = payee; // suppress
    let authorized_signer = Pubkey::new_unique();
    let salt: u64 = 42;

    let mint = CreateMint::new(&mut svm, &fee_payer)
        .decimals(6)
        .send()
        .unwrap();
    let (channel, bump) = find_channel_pda(&payer, &payee, &mint, &authorized_signer, salt);

    svm.airdrop(&payer, 1_000_000_000).unwrap();
    svm.airdrop(&treasury_owner(), 1_000_000_000).unwrap();

    let channel_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
        .owner(&channel)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
        .owner(&payer)
        .send()
        .unwrap();
    let treasury = treasury_owner();
    let treasury_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
        .owner(&treasury)
        .send()
        .unwrap();
    svm.airdrop(&splits[0].owner, 1_000_000).ok();
    let recipient_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
        .owner(&splits[0].owner)
        .send()
        .unwrap();

    // Only fund what is actually owed to the recipient. The payer already
    // withdrew `deposit - settled`; the ATA for the payer-refund leg should NOT
    // be topped up because the distribute path must skip that leg when
    // `payer_withdrawn_at != 0`.
    MintTo::new(
        &mut svm,
        &fee_payer,
        &mint,
        &channel_ata,
        paid_out_balance(settled, paid_out),
    )
    .send()
    .unwrap();

    let preimage = build_preimage(&splits);
    let hash = blake3::hash(&preimage);
    seed_channel(
        &mut svm,
        &channel,
        bump,
        1, // Finalized
        salt,
        deposit,
        settled,
        paid_out,
        1_700_000_000, // payer already withdrew
        *hash.as_bytes(),
        &payer,
        &payee,
        &authorized_signer,
        &mint,
    );

    let ix = build_distribute_ix(
        &channel,
        &payer,
        &channel_ata,
        &payer_ata,
        &treasury_ata,
        &mint,
        &token_2022_program_id(),
        &[recipient_ata],
        salt,
        &preimage,
    );
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        blockhash,
    );
    svm.send_transaction(tx).expect("distribute ok");

    // Recipient got their 50% share (of 150k pool = 75k); payer-refund leg did
    // NOT run (so no extra 50k added).
    assert_eq!(token_balance(&svm, &recipient_ata), 75_000);
    assert_eq!(token_balance(&svm, &payer_ata), 75_000);
}

fn paid_out_balance(settled: u64, paid_out: u64) -> u64 {
    settled.saturating_sub(paid_out)
}

#[test]
fn bad_preimage_hash() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);

    // Tamper the on-chain distribution_hash so the rehash diverges.
    let mut acct = s.svm.get_account(&s.channel).unwrap();
    acct.data[56] ^= 0xFF;
    s.svm
        .set_account(s.channel, acct)
        .expect("overwrite channel");
    let res = s.send(s.distribute_ix());
    expect_custom_err(res, PaymentChannelsError::InvalidDistributionHash);
}

#[test]
fn bps_sum_equals_10000() {
    // Two splits summing to exactly 10_000 → strict `<` rejects.
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 5000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 5000,
        },
    ];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    let res = s.send(s.distribute_ix());
    expect_custom_err(res, PaymentChannelsError::InvalidSplitConfig);
}

#[test]
fn bps_zero_rejects() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 0,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    let res = s.send(s.distribute_ix());
    expect_custom_err(res, PaymentChannelsError::InvalidSplitConfig);
}

#[test]
fn token_2022_allowed_mint_and_immutable_owner_account_extensions_succeed() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, 0);
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
    add_account_extension(&mut s.svm, &s.recipient_atas[0], EXT_IMMUTABLE_OWNER, 0);

    s.send(s.distribute_ix()).expect("allowed extensions ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
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
        let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
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
        let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
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
fn num_recipients_zero() {
    // Preimage = [0x00] — one byte, num_recipients=0. The commitment hash in
    // the channel still matches this preimage but the on-chain validator must
    // reject num_recipients=0.
    let splits = vec![];
    let mut svm = load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let payer = Pubkey::new_unique();
    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let salt: u64 = 7;
    let mint = CreateMint::new(&mut svm, &fee_payer)
        .decimals(6)
        .send()
        .unwrap();
    let (channel, bump) = find_channel_pda(&payer, &payee, &mint, &authorized_signer, salt);

    svm.airdrop(&payer, 1_000_000_000).unwrap();
    svm.airdrop(&treasury_owner(), 1_000_000_000).unwrap();
    let channel_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
        .owner(&channel)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
        .owner(&payer)
        .send()
        .unwrap();
    let treasury_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
        .owner(&treasury_owner())
        .send()
        .unwrap();

    let preimage = build_preimage(&splits);
    let hash = blake3::hash(&preimage);
    seed_channel(
        &mut svm,
        &channel,
        bump,
        0,
        salt,
        200_000,
        100_000,
        0,
        0,
        *hash.as_bytes(),
        &payer,
        &payee,
        &authorized_signer,
        &mint,
    );

    let ix = build_distribute_ix(
        &channel,
        &payer,
        &channel_ata,
        &payer_ata,
        &treasury_ata,
        &mint,
        &token_2022_program_id(),
        &[],
        salt,
        &preimage,
    );
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        blockhash,
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::InvalidRecipientCount,
    );
}

#[test]
fn wrong_salt() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.treasury_ata,
        &s.mint,
        &token_2022_program_id(),
        &s.recipient_atas,
        s.salt.wrapping_add(1), // wrong salt
        &s.preimage(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::ChannelAddressMismatch);
}

#[test]
fn wrong_recipient_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    // Replace recipient ATA with some other ATA.
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.treasury_ata,
        &s.mint,
        &token_2022_program_id(),
        &[rogue_ata],
        s.salt,
        &s.preimage(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidRecipientAccount);
}

#[test]
fn wrong_treasury_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    // Swap treasury ATA with a non-treasury ATA.
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &rogue_ata,
        &s.mint,
        &token_2022_program_id(),
        &s.recipient_atas,
        s.salt,
        &s.preimage(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::TreasuryAddressMismatch);
}

#[test]
fn wrong_token_program() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    let system_id = Pubkey::default(); // all-zero = System program
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.treasury_ata,
        &s.mint,
        &system_id,
        &s.recipient_atas,
        s.salt,
        &s.preimage(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidTokenProgram);
}

#[test]
fn pool_zero_rejects() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    // settled == paid_out → pool = 0.
    let (deposit, settled, paid_out) = pool(200_000, 100_000, 100_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, 0);
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
    // status=2 (Closing) is disallowed for distribute.
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 2);
    expect_custom_err(
        s.send(s.distribute_ix()),
        PaymentChannelsError::ChannelNotClosable,
    );
}

#[test]
fn preimage_length_mismatch() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    // Submit a preimage that declares 1 entry but spans 2*34+1 bytes.
    let mut bad = s.preimage();
    bad.extend_from_slice(&[0u8; 34]); // one extra entry's worth of trailing bytes
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.treasury_ata,
        &s.mint,
        &token_2022_program_id(),
        &s.recipient_atas,
        s.salt,
        &bad,
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidPreimageLength);
}

#[test]
fn num_recipients_exceeds_max() {
    // 33 > MAX_DISTRIBUTION_RECIPIENTS = 32. The count guard runs *after*
    // preimage_len bounds-check but *before* `preimage_len == 1 + n*34`
    // consistency, so we can pass a 1-byte preimage containing just `0x21`
    // and trip the count guard without having to build 33 ATAs or match a
    // valid hash.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, 0);
    let preimage = vec![33u8];
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.treasury_ata,
        &s.mint,
        &token_2022_program_id(),
        &s.recipient_atas,
        s.salt,
        &preimage,
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidRecipientCount);
}

#[test]
fn max_recipients_accepted() {
    let recipient = Pubkey::new_unique();
    let splits: Vec<Split> = (0..MAX_DISTRIBUTION_RECIPIENTS)
        .map(|_| Split {
            owner: recipient,
            bps: 1,
        })
        .collect();
    let (deposit, settled, paid_out) = pool(2_000_000, 0, 1_000_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, 0);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(s.recipient_atas.len(), MAX_DISTRIBUTION_RECIPIENTS);
    assert!(
        s.recipient_atas
            .iter()
            .all(|ata| ata == &s.recipient_atas[0])
    );
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 3_200);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}
