//! End-to-end golden-path test for the `open` instruction.
//!
//! Runs the full CPI chain (CreateAccount + CreateAta + token Transfer) via
//! LiteSVM and verifies every field written into the channel account.

use payment_channels::state::{AccountDiscriminator, CURRENT_CHANNEL_VERSION, ChannelStatus};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use litesvm::LiteSVM;

use super::{
    derive_pdas, derive_pdas_with_token_program, open_ix, open_ix_with_token_program,
    setup_funded_svm, setup_funded_svm_with_token_program,
};
use payment_channels::PaymentChannelsError;

use crate::common::{ProgramLoader, TOKEN_2022, expect_custom_err, read_channel};

const SALT: u64 = 42;
const DEPOSIT: u64 = 5_000_000;
const GRACE_PERIOD: u32 = 7200;

#[test]
fn open_sets_channel_fields() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, payer_token_account) = setup_funded_svm(&mut svm, DEPOSIT);
    let (channel, channel_token_account) =
        derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT);

    let ix = open_ix(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &payer_token_account,
        &channel_token_account,
        SALT,
        DEPOSIT,
        GRACE_PERIOD,
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx).expect("open should succeed");

    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.discriminator, AccountDiscriminator::Channel as u8);
        assert_eq!(ch.version, CURRENT_CHANNEL_VERSION);
        assert_eq!(ch.status, ChannelStatus::Open as u8);
        assert_eq!(ch.salt(), SALT, "salt");
        assert_eq!(ch.deposit(), DEPOSIT, "deposit");
        assert_eq!(ch.settled(), 0, "settled");
        assert_eq!(ch.paid_out(), 0, "paid_out");
        assert_eq!(ch.closure_started_at(), 0, "closure_started_at");
        assert_eq!(ch.payer_withdrawn_at(), 0, "payer_withdrawn_at");
        assert_eq!(ch.grace_period(), GRACE_PERIOD);
        assert_ne!(
            ch.distribution_hash, [0u8; 32],
            "distribution_hash must be set"
        );
        assert_eq!(ch.payer.as_ref(), payer.pubkey().as_array(), "payer");
        assert_eq!(ch.payee.as_ref(), payee.as_array(), "payee");
        assert_eq!(
            ch.authorized_signer.as_ref(),
            authorized_signer.as_array(),
            "authorized_signer"
        );
        assert_eq!(ch.mint.as_ref(), mint.as_array(), "mint");
    });
}

#[test]
fn open_with_no_splits_succeeds() {
    // count == 0 collapses to a vanilla two-party channel: pool flows entirely
    // to the payee at `distribute`. The full `open` CPI chain must still run
    // and the on-chain digest must equal blake3(count=0u32 LE) — the
    // canonical preimage for a zero-recipient plan.
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, payer_token_account) = setup_funded_svm(&mut svm, DEPOSIT);
    let (channel, channel_token_account) =
        derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT);

    let ix = open_ix(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &payer_token_account,
        &channel_token_account,
        SALT,
        DEPOSIT,
        GRACE_PERIOD,
        0,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx)
        .expect("open with zero splits should succeed");

    let expected: [u8; 32] = blake3::hash(&0u32.to_le_bytes()).into();
    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Open as u8);
        assert_eq!(ch.distribution_hash, expected, "distribution_hash");
    });
}

#[test]
fn wrong_channel_token_account_rejected() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, payer_token_account) = setup_funded_svm(&mut svm, DEPOSIT);
    let (channel, _) = derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT);
    let wrong_channel_ata = Pubkey::new_unique();

    let ix = open_ix(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &payer_token_account,
        &wrong_channel_ata,
        SALT,
        DEPOSIT,
        GRACE_PERIOD,
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::ChannelAccountMismatch,
    );
}

#[test]
fn open_sets_channel_fields_token_2022() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, payer_token_account) =
        setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
    let (channel, channel_token_account) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        SALT,
        &TOKEN_2022,
    );

    let ix = open_ix_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &payer_token_account,
        &channel_token_account,
        &TOKEN_2022,
        SALT,
        DEPOSIT,
        GRACE_PERIOD,
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx).expect("open should succeed");

    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.discriminator, AccountDiscriminator::Channel as u8);
        assert_eq!(ch.version, CURRENT_CHANNEL_VERSION);
        assert_eq!(ch.status, ChannelStatus::Open as u8);
        assert_eq!(ch.salt(), SALT, "salt");
        assert_eq!(ch.deposit(), DEPOSIT, "deposit");
        assert_eq!(ch.settled(), 0, "settled");
        assert_eq!(ch.paid_out(), 0, "paid_out");
        assert_eq!(ch.closure_started_at(), 0, "closure_started_at");
        assert_eq!(ch.payer_withdrawn_at(), 0, "payer_withdrawn_at");
        assert_eq!(ch.grace_period(), GRACE_PERIOD);
        assert_ne!(
            ch.distribution_hash, [0u8; 32],
            "distribution_hash must be set"
        );
        assert_eq!(ch.payer.as_ref(), payer.pubkey().as_array(), "payer");
        assert_eq!(ch.payee.as_ref(), payee.as_array(), "payee");
        assert_eq!(
            ch.authorized_signer.as_ref(),
            authorized_signer.as_array(),
            "authorized_signer"
        );
        assert_eq!(ch.mint.as_ref(), mint.as_array(), "mint");
    });
}

#[test]
fn open_with_no_splits_succeeds_token_2022() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, payer_token_account) =
        setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
    let (channel, channel_token_account) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        SALT,
        &TOKEN_2022,
    );

    let ix = open_ix_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &payer_token_account,
        &channel_token_account,
        &TOKEN_2022,
        SALT,
        DEPOSIT,
        GRACE_PERIOD,
        0,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx)
        .expect("open with zero splits should succeed");

    let expected: [u8; 32] = blake3::hash(&0u32.to_le_bytes()).into();
    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Open as u8);
        assert_eq!(ch.distribution_hash, expected, "distribution_hash");
    });
}
