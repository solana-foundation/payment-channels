//! Token-2022 extension TLV injection helpers.
//!
//! Mirrors the on-chain extension types the program inspects in
//! `validate_mint` / `validate_token_account`. Tests use these to splice
//! extension records into existing mint/account data so they can verify
//! both the allow-list and the reject-list paths against the real `.so`.

#![allow(dead_code)]

use litesvm::LiteSVM;
use solana_pubkey::Pubkey;

pub const TOKEN_2022_BASE_MINT_LEN: usize = 82;
pub const TOKEN_2022_BASE_ACCOUNT_LEN: usize = 165;
pub const TOKEN_2022_ACCOUNT_TYPE_OFFSET: usize = 165;
pub const TOKEN_2022_TLV_START: usize = TOKEN_2022_ACCOUNT_TYPE_OFFSET + 1;
pub const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
pub const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;

pub const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
pub const EXT_MINT_CLOSE_AUTHORITY: u16 = 3;
pub const EXT_IMMUTABLE_OWNER: u16 = 7;
pub const EXT_MEMO_TRANSFER: u16 = 8;
pub const EXT_CPI_GUARD: u16 = 11;
pub const EXT_TRANSFER_HOOK: u16 = 14;
pub const EXT_METADATA_POINTER: u16 = 18;
pub const EXT_TOKEN_METADATA: u16 = 19;
pub const EXT_GROUP_POINTER: u16 = 20;
pub const EXT_TOKEN_GROUP: u16 = 21;
pub const EXT_GROUP_MEMBER_POINTER: u16 = 22;
pub const EXT_TOKEN_GROUP_MEMBER: u16 = 23;

pub const POINTER_EXTENSION_LEN: usize = 64;
pub const TOKEN_METADATA_MIN_LEN: usize = 80;
pub const TOKEN_GROUP_LEN: usize = 80;
pub const TOKEN_GROUP_MEMBER_LEN: usize = 72;

pub fn add_mint_extension(svm: &mut LiteSVM, mint: &Pubkey, extension_type: u16, value_len: usize) {
    let mut acct = svm.get_account(mint).expect("mint exists");
    add_token_2022_extension(
        &mut acct.data,
        TOKEN_2022_BASE_MINT_LEN,
        TOKEN_2022_ACCOUNT_TYPE_MINT,
        extension_type,
        value_len,
    );
    svm.set_account(*mint, acct).expect("overwrite mint");
}

pub fn add_account_extension(
    svm: &mut LiteSVM,
    token_account: &Pubkey,
    extension_type: u16,
    value_len: usize,
) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    add_token_2022_extension(
        &mut acct.data,
        TOKEN_2022_BASE_ACCOUNT_LEN,
        TOKEN_2022_ACCOUNT_TYPE_ACCOUNT,
        extension_type,
        value_len,
    );
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

pub fn add_token_2022_extension(
    data: &mut Vec<u8>,
    base_len: usize,
    account_type: u8,
    extension_type: u16,
    value_len: usize,
) {
    if data.len() < TOKEN_2022_TLV_START {
        data.resize(TOKEN_2022_TLV_START, 0);
    }
    data[base_len..TOKEN_2022_ACCOUNT_TYPE_OFFSET].fill(0);
    data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] = account_type;
    data.extend_from_slice(&extension_type.to_le_bytes());
    data.extend_from_slice(&(value_len as u16).to_le_bytes());
    data.resize(data.len() + value_len, 0);
}
