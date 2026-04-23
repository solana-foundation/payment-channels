//! Verifies the distribution-hash introspection logic in the `open` instruction.
//!
//! `open` reads the first 32 bytes of the *preceding* instruction's data (via
//! the Instructions sysvar) and compares them against `OpenArgs::distribution_hash`.
//! These tests confirm that a mismatch is rejected before reaching event emission,
//! and that a match proceeds past the hash guard.

use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels::PaymentChannelsError;
use payment_channels::instructions::open::DISCRIMINATOR;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_instructions_sysvar::ID as INSTRUCTIONS_SYSVAR_ID;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const PROGRAM_ID: Pubkey = Pubkey::new_from_array(*payment_channels::ID.as_array());

fn load_mollusk() -> Mollusk {
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

/// Build the Instructions sysvar where:
///   ix[0] (preceding): data starts with `hash`
///   ix[1] (current):   placeholder for `open`
/// `current_index` (last 2 bytes) is patched to 1.
fn build_ix_sysvar(preceding_hash: [u8; 32]) -> (Pubkey, Account) {
    // Prepend the hash; the rest simulates distribution_bytes.
    let mut preceding_data = Vec::with_capacity(64);
    preceding_data.extend_from_slice(&preceding_hash);
    preceding_data.extend_from_slice(b"distribution_bytes_placeholder__"); // 32 bytes

    let ixs = [
        Instruction::new_with_bytes(Pubkey::new_unique(), &preceding_data, vec![]),
        Instruction::new_with_bytes(PROGRAM_ID, &[], vec![]),
    ];
    let (id, mut account) = mollusk_svm::instructions_sysvar::keyed_account(ixs.iter());

    // current_index lives in the last 2 bytes; set it to 1 (open is ix[1]).
    let len = account.data.len();
    account.data[len - 2..].copy_from_slice(&1u16.to_le_bytes());
    (id, account)
}

/// OpenArgs wire layout: discriminator + salt(8) + deposit(8) + grace(4) + hash(32).
fn open_ix_data(distribution_hash: [u8; 32]) -> Vec<u8> {
    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&0u64.to_le_bytes()); // salt
    data.extend_from_slice(&0u64.to_le_bytes()); // deposit
    data.extend_from_slice(&0u32.to_le_bytes()); // grace_period
    data.extend_from_slice(&distribution_hash);
    data
}

fn run_open(preceding_hash: [u8; 32], open_hash: [u8; 32]) -> ProgramResult {
    let mollusk = load_mollusk();
    let (sysvar_id, sysvar_account) = build_ix_sysvar(preceding_hash);

    let payer = Pubkey::new_unique();
    let event_authority = Pubkey::new_unique(); // wrong PDA — intentional

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &open_ix_data(open_hash),
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // payee
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // mint
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // authorized_signer
            AccountMeta::new(Pubkey::new_unique(), false),          // channel
            AccountMeta::new(Pubkey::new_unique(), false),          // payer_token_account
            AccountMeta::new(Pubkey::new_unique(), false),          // channel_token_account
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // token_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // system_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // rent
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(PROGRAM_ID, false), // self_program; stub from cache
        ],
    );

    // Provide explicit accounts for everything except PROGRAM_ID (let mollusk
    // create the executable stub from its program cache).
    let dummy = Account { lamports: 1_000_000, ..Default::default() };
    let accounts: Vec<(Pubkey, Account)> = ix
        .accounts
        .iter()
        .filter(|m| m.pubkey != PROGRAM_ID)
        .map(|m| {
            if m.pubkey == sysvar_id {
                (m.pubkey, sysvar_account.clone())
            } else {
                (m.pubkey, dummy.clone())
            }
        })
        .collect();

    mollusk.process_instruction(&ix, &accounts).program_result
}

/// A mismatched hash must be rejected with `InvalidDistributionHash` before
/// the program reaches event emission.
#[test]
fn hash_mismatch_returns_invalid_distribution_hash() {
    let result = run_open([0xAA; 32], [0xBB; 32]);
    assert_eq!(
        result,
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidDistributionHash as u32
        )),
    );
}

/// A matching hash passes the guard; the program then fails at event emission
/// (wrong `event_authority` PDA), confirming execution advanced past the hash
/// check without returning `InvalidDistributionHash`.
#[test]
fn hash_match_passes_distribution_check() {
    let result = run_open([0xAA; 32], [0xAA; 32]);
    assert_ne!(
        result,
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidDistributionHash as u32
        )),
        "hash check should have passed",
    );
    assert_eq!(
        result,
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidEventAuthority as u32
        )),
        "expected failure at event authority after hash check passes",
    );
}
