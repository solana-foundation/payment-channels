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
use payment_channels::PaymentChannelsError;
use payment_channels::event_engine::{EMIT_EVENT_IX_DISC, EVENT_AUTHORITY_SEED, EVENT_IX_TAG_LE};
use payment_channels::events::Opened;
use payment_channels_client::instructions::{Open, OpenInstructionArgs};
use payment_channels_client::types::OpenArgs;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM_ID: Pubkey = Pubkey::new_from_array(*payment_channels::ID.as_array());

fn load_program() -> LiteSVM {
    let mut svm = LiteSVM::new();
    let path = std::env::var("PAYMENT_CHANNELS_SO")
        .unwrap_or_else(|_| "../../target/deploy/payment_channels.so".into());
    svm.add_program_from_file(PROGRAM_ID, &path)
        .unwrap_or_else(|e| panic!("failed to load {path}: {e:?}"));
    svm
}

fn event_authority() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], &PROGRAM_ID)
}

fn fund(svm: &mut LiteSVM, pubkey: &Pubkey, lamports: u64) {
    svm.airdrop(pubkey, lamports).unwrap();
}

fn build_open_ix(payer: &Pubkey, channel: &Pubkey, args: OpenArgs) -> Instruction {
    let (event_authority_pubkey, _bump) = event_authority();
    Open {
        payer: *payer,
        payee: Pubkey::new_unique(),
        mint: Pubkey::new_unique(),
        authorized_signer: Pubkey::new_unique(),
        channel: *channel,
        payer_token_account: Pubkey::new_unique(),
        channel_token_account: Pubkey::new_unique(),
        token_program: Pubkey::new_unique(),
        system_program: Pubkey::new_unique(),
        rent: Pubkey::new_unique(),
        event_authority: event_authority_pubkey,
        self_program: PROGRAM_ID,
    }
    .instruction(OpenInstructionArgs { open_args: args })
}

fn send_open(
    svm: &mut LiteSVM,
    payer: &Keypair,
    channel: &Pubkey,
    args: OpenArgs,
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let ix = build_open_ix(&payer.pubkey(), channel, args);
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx)
}

#[test]
fn open_emits_opened_event_with_anchor_compatible_wire_format() {
    let mut svm = load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 10_000_000_000);
    let channel = Pubkey::new_unique();

    let args = OpenArgs {
        salt: 1,
        deposit: 100_000_000,
        grace_period: 3_600,
        distribution_hash: [0x42; 32],
    };
    let meta = send_open(&mut svm, &payer, &channel, args).expect("tx ok");

    // Exactly one outer instruction → exactly one inner-ix list.
    assert_eq!(meta.inner_instructions.len(), 1, "expected 1 outer ix");
    let inners = &meta.inner_instructions[0];
    assert_eq!(
        inners.len(),
        1,
        "expected exactly 1 inner ix (self-CPI emit)"
    );

    let inner = &inners[0];
    // `program_id_index` in the compiled tx indexes the outer account list;
    // the self-CPI into our own program resolves to PROGRAM_ID.
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
    let mut svm = load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);
    let attacker = Keypair::new();

    // Send with attacker as signer + sole account — not the event PDA.
    let ix = build_direct_emit_event_ix(&attacker.pubkey(), true, &[]);
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer, &attacker], msg, svm.latest_blockhash());
    let err = svm.send_transaction(tx).expect_err("should fail");
    let expected = PaymentChannelsError::InvalidEventAuthority as u32;
    match err.err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(code, expected, "expected InvalidEventAuthority");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn emit_event_rejects_non_signer_authority() {
    let mut svm = load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);
    let (pda, _bump) = event_authority();

    // Correct PDA address but not marked signer.
    let ix = build_direct_emit_event_ix(&pda, false, &[]);
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    let err = svm.send_transaction(tx).expect_err("should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::MissingRequiredSignature) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn emit_event_rejects_zero_accounts() {
    let mut svm = load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![],
        data: vec![EMIT_EVENT_IX_DISC],
    };
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    let err = svm.send_transaction(tx).expect_err("should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::NotEnoughAccountKeys) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn emit_event_rejects_extra_accounts() {
    let mut svm = load_program();
    let payer = Keypair::new();
    fund(&mut svm, &payer.pubkey(), 1_000_000_000);
    let (pda, _bump) = event_authority();

    // Two accounts (PDA + something else); slice pattern `[event_authority]`
    // matches only exactly 1, so this must fail.
    let ix = build_direct_emit_event_ix(&pda, false, &[Pubkey::new_unique()]);
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    let err = svm.send_transaction(tx).expect_err("should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::NotEnoughAccountKeys) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}
