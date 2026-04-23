mod channel_fields;
mod distribution_plan;

use payment_channels::instructions::open::{DISCRIMINATOR, MAX_DISTRIBUTION_RECIPIENTS};

pub(super) const PROGRAM_ID: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::new_from_array(*payment_channels::ID.as_array());

pub(super) fn so_path() -> String {
    std::env::var("PAYMENT_CHANNELS_SO")
        .unwrap_or_else(|_| "../../target/deploy/payment_channels.so".into())
}

/// Build raw `open` instruction data.
///
/// Wire layout: `discriminator(1) | salt(8) | deposit(8) | grace(4) |
/// num_recipients(1) | entries(MAX×40)`. Active entries (indices 0..num_recipients)
/// are given distinct non-zero values; trailing entries are zeroed.
pub(super) fn open_ix_data(
    salt: u64,
    deposit: u64,
    grace_period: u32,
    num_recipients: u8,
) -> Vec<u8> {
    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&grace_period.to_le_bytes());
    data.push(num_recipients);
    for i in 0..MAX_DISTRIBUTION_RECIPIENTS {
        if (i as u8) < num_recipients {
            data.extend_from_slice(&[i as u8 + 1; 32]);
            data.extend_from_slice(&(1000u64 + i as u64).to_le_bytes());
        } else {
            data.extend_from_slice(&[0u8; 40]);
        }
    }
    data
}
