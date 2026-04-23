//! Integration test: `open` initializes all `Channel` fields correctly.
//!
//! Uses LiteSVM (with litesvm-token) to run the full instruction including
//! all CPIs: CreateAccount, CreateAta, and the token Transfer.

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::event_engine::event_authority_pda;
use payment_channels::instructions::open::{DISCRIMINATOR, MAX_DISTRIBUTION_RECIPIENTS};
use payment_channels::state::{AccountDiscriminator, CURRENT_CHANNEL_VERSION, Channel, ChannelStatus};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::{Pubkey, pubkey};
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_ID: Pubkey = Pubkey::new_from_array(*payment_channels::ID.as_array());
const EVENT_AUTHORITY: Pubkey = Pubkey::new_from_array(*event_authority_pda::ID.as_array());

const SPL_TOKEN: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
const SYSVAR_RENT: Pubkey = pubkey!("SysvarRent111111111111111111111111111111111");

const SALT: u64 = 42;
const DEPOSIT: u64 = 5_000_000;
const GRACE_PERIOD: u32 = 7200;

fn load_svm() -> LiteSVM {
    let path = std::env::var("PAYMENT_CHANNELS_SO")
        .unwrap_or_else(|_| "../../target/deploy/payment_channels.so".into());
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(PROGRAM_ID, &path)
        .unwrap_or_else(|e| panic!("failed to load {path}: {e:?}"));
    svm
}

fn open_ix_data(num_recipients: u8) -> Vec<u8> {
    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&SALT.to_le_bytes());
    data.extend_from_slice(&DEPOSIT.to_le_bytes());
    data.extend_from_slice(&GRACE_PERIOD.to_le_bytes());
    data.push(num_recipients);
    for i in 0..MAX_DISTRIBUTION_RECIPIENTS {
        if (i as u8) < num_recipients {
            data.extend_from_slice(&[i as u8 + 1; 32]); // recipient
            data.extend_from_slice(&(1000u64 + i as u64).to_le_bytes()); // amount
        } else {
            data.extend_from_slice(&[0u8; 40]);
        }
    }
    data
}

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
    let mut svm = load_svm();

    let payer = Keypair::new();
    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();

    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    // Create a mint owned by SPL Token (not Token-2022, which is the default
    // when litesvm-token is built with features = ["token-2022"]).
    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();

    // Create the payer's token account and mint the deposit amount into it.
    let payer_token_account = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_token_account, DEPOSIT)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();

    // Derive the channel PDA.
    let (channel, _) = Pubkey::find_program_address(
        &[
            b"channel",
            payer.pubkey().as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &SALT.to_le_bytes(),
        ],
        &PROGRAM_ID,
    );

    // Derive the channel escrow ATA: seeds = [channel, token_program, mint].
    let (channel_token_account, _) = Pubkey::find_program_address(
        &[channel.as_ref(), SPL_TOKEN.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &open_ix_data(1),
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(payee, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(authorized_signer, false),
            AccountMeta::new(channel, false),
            AccountMeta::new(payer_token_account, false),
            AccountMeta::new(channel_token_account, false),
            AccountMeta::new_readonly(SPL_TOKEN, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(SYSVAR_RENT, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(EVENT_AUTHORITY, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    );

    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx).expect("open should succeed");

    let channel_data = svm.get_account(&channel).expect("channel account missing").data;

    assert_eq!(channel_data.len(), Channel::LEN, "channel data length");

    // Channel layout (repr C, packed):
    //   0: discriminator      (u8)
    //   1: version            (u8)
    //   2: bump               (u8)
    //   3: status             (u8)
    //   4: salt               (u64)
    //  12: deposit            (u64)
    //  20: settled            (u64)
    //  28: paid_out           (u64)
    //  36: closure_started_at (i64)
    //  44: payer_withdrawn_at (i64)
    //  52: grace_period       (u32)
    //  56: distribution_hash  ([u8; 32])
    //  88: payer              ([u8; 32])
    // 120: payee              ([u8; 32])
    // 152: authorized_signer  ([u8; 32])
    // 184: mint               ([u8; 32])

    assert_eq!(channel_data[0], AccountDiscriminator::Channel as u8);
    assert_eq!(channel_data[1], CURRENT_CHANNEL_VERSION);
    // channel_data[2] = bump: any valid PDA bump
    assert_eq!(channel_data[3], ChannelStatus::Open as u8);
    assert_eq!(read_u64(&channel_data, 4), SALT, "salt");
    assert_eq!(read_u64(&channel_data, 12), DEPOSIT, "deposit");
    assert_eq!(read_u64(&channel_data, 20), 0, "settled");
    assert_eq!(read_u64(&channel_data, 28), 0, "paid_out");
    assert_eq!(read_i64(&channel_data, 36), 0, "closure_started_at");
    assert_eq!(read_i64(&channel_data, 44), 0, "payer_withdrawn_at");
    assert_eq!(read_u32(&channel_data, 52), GRACE_PERIOD);
    assert_ne!(&channel_data[56..88], &[0u8; 32], "distribution_hash must be set");
    assert_eq!(&channel_data[88..120], payer.pubkey().as_array(), "payer");
    assert_eq!(&channel_data[120..152], payee.as_array(), "payee");
    assert_eq!(&channel_data[152..184], authorized_signer.as_array(), "authorized_signer");
    assert_eq!(&channel_data[184..216], mint.as_array(), "mint");
}
