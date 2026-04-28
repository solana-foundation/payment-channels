//! End-to-end golden-path test for the `open` instruction.
//!
//! Runs the full CPI chain (CreateAccount + CreateAta + token Transfer) via
//! LiteSVM and verifies every field written into the channel account.

use payment_channels::state::{
    AccountDiscriminator, CURRENT_CHANNEL_VERSION, Channel, ChannelStatus,
};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use litesvm::LiteSVM;

use super::{derive_pdas, open_ix, setup_funded_svm};
use crate::common::ProgramLoader;

const SALT: u64 = 42;
const DEPOSIT: u64 = 5_000_000;
const GRACE_PERIOD: u32 = 7200;

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_i64(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

#[test]
fn open_sets_channel_fields() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
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

    let channel_data = svm
        .get_account(&channel)
        .expect("channel account missing")
        .data;

    assert_eq!(channel_data.len(), Channel::LEN, "channel data length");

    // Channel layout (repr C, all fields align-1):
    //   0: discriminator      (u8)
    //   1: version            (u8)
    //   2: bump               (u8)
    //   3: status             (u8)
    //   4: salt               ([u8;8])
    //  12: deposit            ([u8;8])
    //  20: settled            ([u8;8])
    //  28: paid_out           ([u8;8])
    //  36: closure_started_at ([u8;8])
    //  44: payer_withdrawn_at ([u8;8])
    //  52: grace_period       ([u8;4])
    //  56: distribution_hash  ([u8;32])
    //  88: payer              ([u8;32])
    // 120: payee              ([u8;32])
    // 152: authorized_signer  ([u8;32])
    // 184: mint               ([u8;32])

    assert_eq!(channel_data[0], AccountDiscriminator::Channel as u8);
    assert_eq!(channel_data[1], CURRENT_CHANNEL_VERSION);
    assert_eq!(channel_data[3], ChannelStatus::Open as u8);
    assert_eq!(read_u64(&channel_data, 4), SALT, "salt");
    assert_eq!(read_u64(&channel_data, 12), DEPOSIT, "deposit");
    assert_eq!(read_u64(&channel_data, 20), 0, "settled");
    assert_eq!(read_u64(&channel_data, 28), 0, "paid_out");
    assert_eq!(read_i64(&channel_data, 36), 0, "closure_started_at");
    assert_eq!(read_i64(&channel_data, 44), 0, "payer_withdrawn_at");
    assert_eq!(read_u32(&channel_data, 52), GRACE_PERIOD);
    assert_ne!(
        &channel_data[56..88],
        &[0u8; 32],
        "distribution_hash must be set"
    );
    assert_eq!(&channel_data[88..120], payer.pubkey().as_array(), "payer");
    assert_eq!(&channel_data[120..152], payee.as_array(), "payee");
    assert_eq!(
        &channel_data[152..184],
        authorized_signer.as_array(),
        "authorized_signer"
    );
    assert_eq!(&channel_data[184..216], mint.as_array(), "mint");
}

#[test]
fn open_with_no_splits_succeeds() {
    // count == 0 collapses to a vanilla two-party channel: pool flows entirely
    // to the payee at `distribute`. The full `open` CPI chain must still run
    // and the on-chain digest must equal blake3(&[0u8]) — the canonical preimage
    // for a zero-recipient plan.
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
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

    let channel_data = svm
        .get_account(&channel)
        .expect("channel account missing")
        .data;

    assert_eq!(channel_data.len(), Channel::LEN);
    assert_eq!(channel_data[3], ChannelStatus::Open as u8);

    // distribution_hash == blake3(&[0u8]) — locked at `open` from the
    // canonical preimage `count(1)` with no entries.
    let expected: [u8; 32] = blake3::hash(&[0u8]).into();
    assert_eq!(&channel_data[56..88], &expected, "distribution_hash");
}
