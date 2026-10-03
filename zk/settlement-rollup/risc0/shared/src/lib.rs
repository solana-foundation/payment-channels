use borsh::{BorshDeserialize, BorshSerialize};

pub const V1_PAYLOAD_LEN: usize = 50;
pub const V1_MAGIC: [u8; 2] = [0x56, 0x01];

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct V1VoucherInput {
    pub payload: Vec<u8>,
    pub authorized_signer: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct V1VoucherJournal {
    pub channel_id: [u8; 32],
    pub cumulative_amount: u64,
    pub expires_at: i64,
}
