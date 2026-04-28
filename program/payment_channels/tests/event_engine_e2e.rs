//! End-to-end validation of the event engine against the compiled .so.
//!
//! Exercises the self-CPI path by invoking `open` (which emits an `Opened`
//! event) and inspecting the resulting inner instruction against an
//! Anchor-style decoder. Negative tests defend the `emit_event` authority
//! validation surface.

// `FailedTransactionMetadata` from litesvm is large by design; boxing it
// in our test harness is churn for no benefit.
#![allow(clippy::result_large_err)]
// Our `ProgramError::NotEnoughAccountKeys` still round-trips through the
// runtime as `InstructionError::NotEnoughAccountKeys`; the renamed
// `MissingAccount` variant is a separate enum member that wouldn't match.
#![allow(deprecated)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels::event_engine::{EMIT_EVENT_IX_DISC, EVENT_AUTHORITY_SEED, EVENT_IX_TAG_LE};
use payment_channels::events::Opened;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::{Pubkey, pubkey};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

mod common;
use common::{PROGRAM_ID, ProgramLoader, expect_custom_err};

const SPL_TOKEN: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
const SYSVAR_RENT: Pubkey = pubkey!("SysvarRent111111111111111111111111111111111");

fn event_authority() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], &PROGRAM_ID)
}

fn fund(svm: &mut LiteSVM, pubkey: &Pubkey, lamports: u64) {
    svm.airdrop(pubkey, lamports).unwrap();
}

#[test]
fn open_emits_opened_event_with_anchor_compatible_wire_format() {
    use payment_channels::instructions::open::{DISCRIMINATOR, MAX_DISTRIBUTION_RECIPIENTS};

    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 10_000_000_000);

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let salt: u64 = 1;
    let deposit: u64 = 100_000_000;
    let grace_period: u32 = 3_600;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();

    let (channel, _) = Pubkey::find_program_address(
        &[
            b"channel",
            payer.pubkey().as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
        ],
        &PROGRAM_ID,
    );
    let (channel_ata, _) = Pubkey::find_program_address(
        &[channel.as_ref(), SPL_TOKEN.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );
    let (event_auth, _) = event_authority();

    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&grace_period.to_le_bytes());
    data.push(1u8); // num_recipients
    data.extend_from_slice(&[1u8; 32]); // recipient pubkey
    data.extend_from_slice(&deposit.to_le_bytes()); // amount
    data.extend_from_slice(&[0u8; (MAX_DISTRIBUTION_RECIPIENTS - 1) * 40]);

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(payee, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(authorized_signer, false),
            AccountMeta::new(channel, false),
            AccountMeta::new(payer_ata, false),
            AccountMeta::new(channel_ata, false),
            AccountMeta::new_readonly(SPL_TOKEN, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(SYSVAR_RENT, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(event_auth, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    let meta = svm.send_transaction(tx).expect("tx ok");

    // Exactly one outer instruction → exactly one inner-ix list.
    assert_eq!(meta.inner_instructions.len(), 1, "expected 1 outer ix");
    let inners = &meta.inner_instructions[0];

    // Find the emit_event self-CPI: its data begins with the 8-byte Anchor
    // event tag, distinguishing it from the other CPIs (CreateAccount,
    // CreateAta, Transfer) also made by `open`.
    let inner = inners
        .iter()
        .find(|ix| ix.instruction.data.starts_with(&EVENT_IX_TAG_LE))
        .expect("expected emit_event inner instruction");

    // stack_height should be 2 (outer ix = 1, CPI pushes to 2).
    assert_eq!(
        inner.stack_height, 2,
        "self-CPI should be at stack height 2"
    );

    // Anchor-style parse:
    //   [0..8)   tag          = EVENT_IX_TAG_LE
    //   [8..16)  event_disc   = Opened::DISCRIMINATOR (sha256("event:Opened")[..8])
    //   [16..48) borsh body   = channel as [u8; 32]
    let data = &inner.instruction.data;
    assert_eq!(data.len(), 48, "wire length = 8 tag + 8 disc + 32 channel");
    assert_eq!(&data[..8], &EVENT_IX_TAG_LE);

    // `borsh::from_slice` on the remainder (skipping the 8-byte anchor tag)
    // should decode as the Anchor-client discriminated union: 8 disc bytes
    // then borsh body. For a single known event type, we just split and
    // decode the body directly.
    let disc = &data[8..16];
    let body = &data[16..];
    let expected_disc =
        <Opened as payment_channels::event_engine::EventDiscriminator>::DISCRIMINATOR;
    assert_eq!(disc, &expected_disc, "event discriminator mismatch");

    // Manual parse of the 32-byte Borsh payload. We intentionally skip
    // adding `BorshDeserialize` to the `Opened` struct in the runtime
    // crate — programs emit events, they don't read them. Off-chain
    // indexers are the consumers and will add their own deserialization.
    let channel_bytes: [u8; 32] = body.try_into().expect("32-byte borsh body");
    assert_eq!(channel_bytes, channel.to_bytes());
}

fn build_direct_emit_event_ix(
    authority: &Pubkey,
    signed: bool,
    extra_accounts: &[Pubkey],
) -> Instruction {
    let mut accounts = vec![AccountMeta {
        pubkey: *authority,
        is_signer: signed,
        is_writable: false,
    }];
    for extra in extra_accounts {
        accounts.push(AccountMeta::new_readonly(*extra, false));
    }
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data: vec![EMIT_EVENT_IX_DISC],
    }
}

#[test]
fn emit_event_rejects_bad_authority() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);
    let attacker = Keypair::new();

    // Send with attacker as signer + sole account — not the event PDA.
    let ix = build_direct_emit_event_ix(&attacker.pubkey(), true, &[]);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::InvalidEventAuthority,
    );
}

#[test]
fn emit_event_rejects_non_signer_authority() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);
    let (pda, _bump) = event_authority();

    // Correct PDA address but not marked signer.
    let ix = build_direct_emit_event_ix(&pda, false, &[]);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    let err = svm.send_transaction(tx).expect_err("should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::MissingRequiredSignature) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn emit_event_rejects_zero_accounts() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![],
        data: vec![EMIT_EVENT_IX_DISC],
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    let err = svm.send_transaction(tx).expect_err("should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::NotEnoughAccountKeys) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn emit_event_rejects_extra_accounts() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);
    let (pda, _bump) = event_authority();

    // Two accounts (PDA + something else); slice pattern `[event_authority]`
    // matches only exactly 1, so this must fail.
    let ix = build_direct_emit_event_ix(&pda, false, &[Pubkey::new_unique()]);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    let err = svm.send_transaction(tx).expect_err("should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::NotEnoughAccountKeys) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}
