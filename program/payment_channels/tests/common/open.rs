//! Shared `open` instruction helpers reused across multiple test binaries.
//!
//! Lifted out of `tests/open/mod.rs` so other suites (e.g. `distribute`) can
//! reuse them without compiling that suite's `#[test]` fns into their
//! binary.

#![allow(dead_code)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use mollusk_svm::Mollusk;
use payment_channels::event_engine::event_authority_pda;
use payment_channels::instructions::open::{DISCRIMINATOR, MAX_DISTRIBUTION_RECIPIENTS};
use payment_channels::state::Channel;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::{Pubkey, pubkey};
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::PROGRAM_ID;

pub const SPL_TOKEN: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
pub const SYSVAR_RENT: Pubkey = pubkey!("SysvarRent111111111111111111111111111111111");
pub const EVENT_AUTHORITY: Pubkey = Pubkey::new_from_array(*event_authority_pda::ID.as_array());

/// One distribution split: recipient owner pubkey + bps share.
#[derive(Clone, Copy)]
pub struct Split {
    pub owner: Pubkey,
    pub bps: u16,
}

/// Build raw `open` instruction data with synthetic split entries.
///
/// Active entries (indices 0..num_recipients) get distinct non-zero recipient
/// bytes and `bps = i+1`; trailing entries are zeroed. Used by negative tests
/// (`tests/open/bounds.rs`, `accounts.rs`, `distribution.rs`) that exercise
/// arg-validation without caring about recipient identities.
pub fn open_ix_data(salt: u64, deposit: u64, grace_period: u32, num_recipients: u8) -> Vec<u8> {
    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&grace_period.to_le_bytes());
    data.push(num_recipients);
    for i in 0..MAX_DISTRIBUTION_RECIPIENTS {
        if (i as u8) < num_recipients {
            data.extend_from_slice(&[i as u8 + 1; 32]);
            data.extend_from_slice(&(i as u16 + 1).to_le_bytes());
        } else {
            data.extend_from_slice(&[0u8; 34]);
        }
    }
    data
}

/// Build raw `open` instruction data from explicit splits.
///
/// Wire layout: `discriminator(1) | salt(8) | deposit(8) | grace(4) |
/// num_recipients(1) | entries(MAX×34)`. Entries beyond `splits.len()` are
/// zeroed. Used by `distribute` tests that need the channel's
/// `distribution_hash` to match an externally-built preimage byte-for-byte.
pub fn open_ix_data_for_splits(
    salt: u64,
    deposit: u64,
    grace_period: u32,
    splits: &[Split],
) -> Vec<u8> {
    assert!(splits.len() <= MAX_DISTRIBUTION_RECIPIENTS);
    let mut data = vec![DISCRIMINATOR];
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

/// Load a Mollusk instance with the compiled program.
pub fn load_mollusk() -> Mollusk {
    let path = std::env::var("PAYMENT_CHANNELS_SO")
        .unwrap_or_else(|_| "../../target/deploy/payment_channels.so".into());
    let elf = mollusk_svm::file::read_file(&path);
    let mut m = Mollusk::default();
    m.add_program_with_loader_and_elf(
        &PROGRAM_ID,
        &mollusk_svm::program::loader_keys::LOADER_V3,
        &elf,
    );
    m
}

/// Run `open` with a signed payer and dummy accounts.
///
/// Fails at arg validation (`InvalidInstructionData`) if the data is invalid,
/// or advances past it and fails at the channel-address check
/// (`InvalidAccountData`) because the dummy channel pubkey is not the derived
/// PDA.
pub fn run_open(ix_data: Vec<u8>) -> mollusk_svm::result::ProgramResult {
    let mollusk = load_mollusk();

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &ix_data,
        vec![
            AccountMeta::new(Pubkey::new_unique(), true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    );

    let dummy = Account {
        lamports: 1_000_000,
        ..Default::default()
    };
    // Channel account needs Channel::LEN bytes so init_at's size check passes
    // and execution reaches the channel-address guard.
    let channel_account = Account {
        lamports: 1_000_000,
        data: vec![0u8; Channel::LEN],
        ..Default::default()
    };
    let accounts: Vec<(Pubkey, Account)> = ix
        .accounts
        .iter()
        .filter(|m| m.pubkey != PROGRAM_ID)
        .map(|m| {
            let acc = if m.pubkey == ix.accounts[4].pubkey {
                channel_account.clone()
            } else {
                dummy.clone()
            };
            (m.pubkey, acc)
        })
        .collect();

    mollusk.process_instruction(&ix, &accounts).program_result
}

/// Airdrop, create mint, mint `deposit` tokens to payer's ATA (SPL Token).
pub fn setup_funded_svm(svm: &mut LiteSVM, deposit: u64) -> (Keypair, Pubkey, Pubkey) {
    setup_funded_svm_with_token_program(svm, deposit, &SPL_TOKEN)
}

/// Airdrop, create mint, mint `deposit` tokens to payer's ATA under
/// `token_program`. Returns `(payer_keypair, mint, payer_token_account)`.
pub fn setup_funded_svm_with_token_program(
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

/// Derive `(channel_pda, channel_ata)` for the given seeds (SPL Token).
pub fn derive_pdas(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
) -> (Pubkey, Pubkey) {
    derive_pdas_with_token_program(payer, payee, mint, authorized_signer, salt, &SPL_TOKEN)
}

/// Derive `(channel_pda, channel_ata)` for the given seeds and token program.
pub fn derive_pdas_with_token_program(
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

/// Build the `open` instruction with all 13 accounts wired up (SPL Token).
#[allow(clippy::too_many_arguments)]
pub fn open_ix(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    channel: &Pubkey,
    payer_token_account: &Pubkey,
    channel_token_account: &Pubkey,
    salt: u64,
    deposit: u64,
    grace_period: u32,
    num_recipients: u8,
) -> Instruction {
    open_ix_with_token_program(
        payer,
        payee,
        mint,
        authorized_signer,
        channel,
        payer_token_account,
        channel_token_account,
        &SPL_TOKEN,
        salt,
        deposit,
        grace_period,
        num_recipients,
    )
}

/// Build the `open` instruction with synthetic splits (recipient bytes
/// `[i+1; 32]`, `bps = i+1`). For negative tests of arg validation that
/// don't care about recipient identities.
#[allow(clippy::too_many_arguments)]
pub fn open_ix_with_token_program(
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
    num_recipients: u8,
) -> Instruction {
    open_ix_inner(
        payer,
        payee,
        mint,
        authorized_signer,
        channel,
        payer_token_account,
        channel_token_account,
        token_program,
        open_ix_data(salt, deposit, grace_period, num_recipients),
    )
}

/// Build the `open` instruction with explicit splits.
#[allow(clippy::too_many_arguments)]
pub fn open_ix_for_splits(
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
    open_ix_inner(
        payer,
        payee,
        mint,
        authorized_signer,
        channel,
        payer_token_account,
        channel_token_account,
        token_program,
        open_ix_data_for_splits(salt, deposit, grace_period, splits),
    )
}

#[allow(clippy::too_many_arguments)]
fn open_ix_inner(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    channel: &Pubkey,
    payer_token_account: &Pubkey,
    channel_token_account: &Pubkey,
    token_program: &Pubkey,
    data: Vec<u8>,
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
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
            AccountMeta::new_readonly(EVENT_AUTHORITY, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

/// Output of [`open_channel`] — everything a downstream test needs to chain
/// `settle` / `distribute` calls against the freshly-opened channel.
pub struct OpenedChannel {
    pub channel: Pubkey,
    pub channel_ata: Pubkey,
    pub payee: Pubkey,
    pub authorized_signer: Keypair,
    pub salt: u64,
}

/// End-to-end open: derive PDAs, build and submit the `open` ix, return the
/// pubkeys plus the authorized-signer keypair (the caller will need it to
/// sign settle vouchers).
#[allow(clippy::too_many_arguments)]
pub fn open_channel(
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
        salt,
    }
}
