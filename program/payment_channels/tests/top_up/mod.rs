mod accounts;
mod bounds;

use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels::instructions::top_up::DISCRIMINATOR;
use payment_channels::state::Channel;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::common::PROGRAM_ID;

pub(super) const DEPOSIT: u64 = 1_000_000;

/// Build raw `topUp` instruction data.
///
/// Wire layout: `discriminator(1) | amount(8)`.
pub(super) fn top_up_ix_data(amount: u64) -> Vec<u8> {
    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

/// Build a 216-byte Channel blob with the given status, deposit, and payer.
pub(super) fn channel_data(status: u8, deposit: u64, payer: &Pubkey) -> Vec<u8> {
    let mut data = vec![0u8; Channel::LEN];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[3] = status;
    data[12..20].copy_from_slice(&deposit.to_le_bytes());
    data[88..120].copy_from_slice(&payer.to_bytes());
    data
}

/// Load a Mollusk instance with the compiled program.
pub(super) fn load_mollusk() -> Mollusk {
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

/// Run `topUp` through Mollusk with a seeded channel at account index 1.
///
/// Fails at the signer check if `is_signer` is false, at arg validation if
/// `amount` is 0, or at channel validation if status/payer checks fire.
/// Never reaches the token CPI.
pub(super) fn run_top_up(
    payer: &Pubkey,
    is_signer: bool,
    channel_blob: Vec<u8>,
    amount: u64,
) -> ProgramResult {
    let mollusk = load_mollusk();

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &top_up_ix_data(amount),
        vec![
            AccountMeta::new(*payer, is_signer),
            AccountMeta::new(Pubkey::new_unique(), false), // channel
            AccountMeta::new(Pubkey::new_unique(), false), // payer_token_account
            AccountMeta::new(Pubkey::new_unique(), false), // channel_token_account
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // mint
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // token_program
        ],
    );

    let channel_account = Account {
        lamports: 10_000_000,
        data: channel_blob,
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    };
    let dummy = Account {
        lamports: 1_000_000,
        ..Default::default()
    };

    let accounts: Vec<(Pubkey, Account)> = ix
        .accounts
        .iter()
        .map(|m| {
            let acc = if m.pubkey == ix.accounts[1].pubkey {
                channel_account.clone()
            } else {
                dummy.clone()
            };
            (m.pubkey, acc)
        })
        .collect();

    mollusk.process_instruction(&ix, &accounts).program_result
}
