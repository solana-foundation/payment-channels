//! Token-2022 extension TLV injection helpers.
//!
//! Mirrors the on-chain extension types the program inspects in
//! `validate_mint` / `validate_token_account`. Tests use these to splice
//! extension records into existing mint/account data so they can verify
//! both the allow-list and the reject-list paths against the real `.so`.

#![allow(dead_code)]

use core::mem::{offset_of, size_of};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use spl_token_2022_interface::extension::{
    ExtensionType, ExtensionType as Upstream,
    confidential_transfer::ConfidentialTransferMint,
    confidential_transfer_fee::ConfidentialTransferFeeConfig,
    interest_bearing_mint::InterestBearingConfig,
    metadata_pointer::MetadataPointer,
    mint_close_authority::MintCloseAuthority,
    pausable::PausableConfig,
    permanent_delegate::PermanentDelegate,
    scaled_ui_amount::ScaledUiAmountConfig,
    transfer_fee::{TransferFee, TransferFeeConfig},
    transfer_hook::TransferHook,
};
use spl_token_2022_interface::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey;
use spl_token_2022_interface::state::{Account as TokenAccount, AccountState, Mint};

use super::TOKEN_2022;

pub const TOKEN_2022_BASE_MINT_LEN: usize = 82;
pub const TOKEN_2022_BASE_ACCOUNT_LEN: usize = 165;
pub const TOKEN_2022_ACCOUNT_TYPE_OFFSET: usize = 165;
pub const TOKEN_2022_TLV_START: usize = TOKEN_2022_ACCOUNT_TYPE_OFFSET + 1;
pub const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
pub const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
/// Offset of the `Account.state` byte in the 165-byte SPL/Token-2022 base
/// layout: mint (32) + owner (32) + amount (8) + delegate `COption` (4 + 32).
pub const TOKEN_ACCOUNT_STATE_OFFSET: usize = 108;

pub const EXT_TRANSFER_FEE_CONFIG: u16 = Upstream::TransferFeeConfig as u16;
pub const EXT_TRANSFER_FEE_AMOUNT: u16 = Upstream::TransferFeeAmount as u16;
pub const EXT_MINT_CLOSE_AUTHORITY: u16 = Upstream::MintCloseAuthority as u16;
pub const EXT_CONFIDENTIAL_TRANSFER_MINT: u16 = Upstream::ConfidentialTransferMint as u16;
pub const EXT_CONFIDENTIAL_TRANSFER_ACCOUNT: u16 = Upstream::ConfidentialTransferAccount as u16;
pub const EXT_DEFAULT_ACCOUNT_STATE: u16 = Upstream::DefaultAccountState as u16;
pub const EXT_IMMUTABLE_OWNER: u16 = Upstream::ImmutableOwner as u16;
pub const EXT_MEMO_TRANSFER: u16 = Upstream::MemoTransfer as u16;
pub const EXT_NON_TRANSFERABLE: u16 = Upstream::NonTransferable as u16;
pub const EXT_INTEREST_BEARING_CONFIG: u16 = Upstream::InterestBearingConfig as u16;
pub const EXT_CPI_GUARD: u16 = Upstream::CpiGuard as u16;
pub const EXT_PERMANENT_DELEGATE: u16 = Upstream::PermanentDelegate as u16;
pub const EXT_TRANSFER_HOOK: u16 = Upstream::TransferHook as u16;
pub const EXT_TRANSFER_HOOK_ACCOUNT: u16 = Upstream::TransferHookAccount as u16;
pub const EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG: u16 =
    Upstream::ConfidentialTransferFeeConfig as u16;
pub const EXT_METADATA_POINTER: u16 = Upstream::MetadataPointer as u16;
pub const EXT_TOKEN_METADATA: u16 = Upstream::TokenMetadata as u16;
pub const EXT_GROUP_POINTER: u16 = Upstream::GroupPointer as u16;
pub const EXT_TOKEN_GROUP: u16 = Upstream::TokenGroup as u16;
pub const EXT_GROUP_MEMBER_POINTER: u16 = Upstream::GroupMemberPointer as u16;
pub const EXT_TOKEN_GROUP_MEMBER: u16 = Upstream::TokenGroupMember as u16;
pub const EXT_SCALED_UI_AMOUNT: u16 = Upstream::ScaledUiAmount as u16;
pub const EXT_PAUSABLE: u16 = Upstream::Pausable as u16;
pub const EXT_PAUSABLE_ACCOUNT: u16 = Upstream::PausableAccount as u16;

pub const POINTER_EXTENSION_LEN: usize = size_of::<MetadataPointer>();
pub const TOKEN_METADATA_MIN_LEN: usize = 80;
pub const TOKEN_GROUP_LEN: usize = 80;
pub const TOKEN_GROUP_MEMBER_LEN: usize = 72;
pub const TRANSFER_FEE_CONFIG_LEN: usize = size_of::<TransferFeeConfig>();
pub const TRANSFER_HOOK_LEN: usize = size_of::<TransferHook>();
pub const PERMANENT_DELEGATE_LEN: usize = size_of::<PermanentDelegate>();
pub const MINT_CLOSE_AUTHORITY_LEN: usize = size_of::<MintCloseAuthority>();
pub const INTEREST_BEARING_CONFIG_LEN: usize = size_of::<InterestBearingConfig>();
pub const SCALED_UI_AMOUNT_LEN: usize = size_of::<ScaledUiAmountConfig>();
pub const PAUSABLE_LEN: usize = size_of::<PausableConfig>();
pub const CONFIDENTIAL_TRANSFER_MINT_LEN: usize = size_of::<ConfidentialTransferMint>();
pub const CONFIDENTIAL_TRANSFER_FEE_CONFIG_LEN: usize = size_of::<ConfidentialTransferFeeConfig>();
pub const TRANSFER_FEE_OLDER_OFFSET: usize = offset_of!(TransferFeeConfig, older_transfer_fee);
pub const TRANSFER_FEE_NEWER_OFFSET: usize = offset_of!(TransferFeeConfig, newer_transfer_fee);
pub const TRANSFER_FEE_EPOCH_OFFSET: usize = offset_of!(TransferFee, epoch);
pub const TRANSFER_FEE_MAX_OFFSET: usize = offset_of!(TransferFee, maximum_fee);
pub const TRANSFER_FEE_BPS_OFFSET: usize = offset_of!(TransferFee, transfer_fee_basis_points);
pub const TRANSFER_FEE_NEWER_BPS_OFFSET: usize =
    TRANSFER_FEE_NEWER_OFFSET + TRANSFER_FEE_BPS_OFFSET;
pub const TRANSFER_FEE_NEWER_MAX_OFFSET: usize =
    TRANSFER_FEE_NEWER_OFFSET + TRANSFER_FEE_MAX_OFFSET;
pub const TRANSFER_HOOK_PROGRAM_ID_OFFSET: usize = offset_of!(TransferHook, program_id);

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

/// Appends a truncated mint-extension record, making the TLV trailer malformed.
pub fn add_malformed_mint_extension(
    svm: &mut LiteSVM,
    mint: &Pubkey,
    extension_type: u16,
    value_len: usize,
) {
    add_mint_extension(svm, mint, extension_type, value_len);
    let mut acct = svm.get_account(mint).expect("mint exists");
    acct.data.pop().expect("extension has a value byte");
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

/// Forces a token account's `state` byte to `state` (e.g. [`AccountState::Frozen`]),
/// simulating a beneficiary that froze or never initialized their canonical ATA.
pub fn set_token_account_state(svm: &mut LiteSVM, token_account: &Pubkey, state: AccountState) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    acct.data[TOKEN_ACCOUNT_STATE_OFFSET] = match state {
        AccountState::Uninitialized => 0,
        AccountState::Initialized => 1,
        AccountState::Frozen => 2,
    };
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

/// Overwrites a token account's `owner` field, simulating a beneficiary that
/// reassigned their canonical ATA via `SetAuthority(AccountOwner)` to an
/// unreachable key (`AccountValidationError::OwnerMismatch`). The ATA address
/// stays occupied, so it cannot be permissionlessly recreated.
pub fn set_token_account_owner(svm: &mut LiteSVM, token_account: &Pubkey, new_owner: &Pubkey) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    // The `owner` lives in the 165-byte base layout
    let mut token = TokenAccount::unpack_from_slice(&acct.data[..TokenAccount::LEN])
        .expect("valid token account");
    token.owner = *new_owner;
    token.pack_into_slice(&mut acct.data[..TokenAccount::LEN]);
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

/// Simulates the beneficiary closing their canonical ATA: drops the account
/// data so the on-chain token-account view can no longer be constructed
/// (`AccountValidationError::MalformedTokenAccountData`).
pub fn close_token_account(svm: &mut LiteSVM, token_account: &Pubkey) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    acct.data.clear();
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

/// Overwrites bytes at `offset` in the payload of the most recently spliced
/// mint extension record (e.g. to make a zero-filled fee config live).
pub fn patch_last_mint_extension(svm: &mut LiteSVM, mint: &Pubkey, offset: usize, value: &[u8]) {
    let mut acct = svm.get_account(mint).expect("mint exists");
    let len = acct.data.len();
    // Walk the TLV trailer to find the start of the last record's payload.
    let mut cursor = TOKEN_2022_TLV_START;
    let mut last_payload = None;
    while cursor + 4 <= len {
        let ty = u16::from_le_bytes([acct.data[cursor], acct.data[cursor + 1]]);
        if ty == 0 {
            break;
        }
        let vlen = u16::from_le_bytes([acct.data[cursor + 2], acct.data[cursor + 3]]) as usize;
        last_payload = Some(cursor + 4);
        cursor += 4 + vlen;
    }
    let start = last_payload.expect("at least one spliced record") + offset;
    acct.data[start..start + value.len()].copy_from_slice(value);
    svm.set_account(*mint, acct).expect("overwrite mint");
}

/// Mainnet PYUSD / USDG mint extensions in TLV order, minus `TokenMetadata`
/// (initialized through a separate interface).
pub const PAXOS_STABLECOIN_MINT_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::MintCloseAuthority,
    ExtensionType::PermanentDelegate,
    ExtensionType::TransferFeeConfig,
    ExtensionType::ConfidentialTransferMint,
    ExtensionType::ConfidentialTransferFeeConfig,
    ExtensionType::TransferHook,
    ExtensionType::MetadataPointer,
];

/// Creates a mint through the real Token-2022 program with the mainnet
/// PYUSD / USDG extension set in its dormant configuration. `authority` holds
/// every issuer power, so tests can activate the fee or hook later.
pub fn create_paxos_style_mint(svm: &mut LiteSVM, authority: &Keypair, decimals: u8) -> Pubkey {
    create_paxos_style_mint_at(svm, authority, &Keypair::new(), decimals)
}

/// [`create_paxos_style_mint`] at a caller-supplied mint keypair.
pub fn create_paxos_style_mint_at(
    svm: &mut LiteSVM,
    authority: &Keypair,
    mint: &Keypair,
    decimals: u8,
) -> Pubkey {
    let space = ExtensionType::try_calculate_account_len::<Mint>(PAXOS_STABLECOIN_MINT_EXTENSIONS)
        .expect("fixed-size extension set");
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    let auth = authority.pubkey();

    let ixs = vec![
        solana_system_interface::instruction::create_account(
            &auth,
            &mint.pubkey(),
            lamports,
            space as u64,
            &TOKEN_2022,
        ),
        spl_token_2022_interface::instruction::initialize_mint_close_authority(
            &TOKEN_2022,
            &mint.pubkey(),
            Some(&auth),
        )
        .unwrap(),
        spl_token_2022_interface::instruction::initialize_permanent_delegate(
            &TOKEN_2022,
            &mint.pubkey(),
            &auth,
        )
        .unwrap(),
        spl_token_2022_interface::extension::transfer_fee::instruction::initialize_transfer_fee_config(
            &TOKEN_2022,
            &mint.pubkey(),
            Some(&auth),
            Some(&auth),
            0,
            0,
        )
        .unwrap(),
        spl_token_2022_interface::extension::confidential_transfer::instruction::initialize_mint(
            &TOKEN_2022,
            &mint.pubkey(),
            Some(auth),
            false,
            None,
        )
        .unwrap(),
        spl_token_2022_interface::extension::confidential_transfer_fee::instruction::initialize_confidential_transfer_fee_config(
            &TOKEN_2022,
            &mint.pubkey(),
            Some(auth),
            &PodElGamalPubkey::default(),
        )
        .unwrap(),
        spl_token_2022_interface::extension::transfer_hook::instruction::initialize(
            &TOKEN_2022,
            &mint.pubkey(),
            Some(auth),
            None,
        )
        .unwrap(),
        spl_token_2022_interface::extension::metadata_pointer::instruction::initialize(
            &TOKEN_2022,
            &mint.pubkey(),
            Some(auth),
            Some(mint.pubkey()),
        )
        .unwrap(),
        spl_token_2022_interface::instruction::initialize_mint2(
            &TOKEN_2022,
            &mint.pubkey(),
            &auth,
            Some(&auth),
            decimals,
        )
        .unwrap(),
    ];
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&auth),
        &[authority, mint],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("paxos-style mint");
    mint.pubkey()
}

/// Issuer action: schedules a transfer fee (lands in `newer_transfer_fee`).
pub fn set_transfer_fee(
    svm: &mut LiteSVM,
    authority: &Keypair,
    mint: &Pubkey,
    bps: u16,
    maximum_fee: u64,
) {
    let ix = spl_token_2022_interface::extension::transfer_fee::instruction::set_transfer_fee(
        &TOKEN_2022,
        mint,
        &authority.pubkey(),
        &[],
        bps,
        maximum_fee,
    )
    .unwrap();
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[authority],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("set transfer fee");
}

/// Issuer action: installs or clears the transfer-hook program.
pub fn set_transfer_hook_program(
    svm: &mut LiteSVM,
    authority: &Keypair,
    mint: &Pubkey,
    program: Option<Pubkey>,
) {
    let ix = spl_token_2022_interface::extension::transfer_hook::instruction::update(
        &TOKEN_2022,
        mint,
        &authority.pubkey(),
        &[],
        program,
    )
    .unwrap();
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[authority],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("update transfer hook");
}

/// Extension type ids present in a Token-2022 account's TLV trailer, in order.
pub fn extension_ids(svm: &LiteSVM, account: &Pubkey) -> Vec<u16> {
    let data = svm.get_account(account).expect("account exists").data;
    let mut ids = Vec::new();
    let mut cursor = TOKEN_2022_TLV_START;
    while cursor + 4 <= data.len() {
        let ty = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        if ty == 0 {
            break;
        }
        let vlen = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        ids.push(ty);
        cursor += 4 + vlen;
    }
    ids
}

/// `(payer, mint, payer_ata)` on a paxos-style mint; the payer is also the issuer.
pub fn setup_paxos_style_funded_svm(svm: &mut LiteSVM, deposit: u64) -> (Keypair, Pubkey, Pubkey) {
    use litesvm_token::{CreateAssociatedTokenAccount, MintTo};

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let mint = create_paxos_style_mint(svm, &payer, 6);
    let payer_ata = CreateAssociatedTokenAccount::new(svm, &payer, &mint)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    MintTo::new(svm, &payer, &mint, &payer_ata, deposit)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    (payer, mint, payer_ata)
}

/// `TransferFeeConfig` payload: `older` governs before `newer_epoch`, `newer`
/// from then on. `fee_config_payload(0, 0)` is the PYUSD / USDG shape.
pub fn fee_schedule_payload(older: (u16, u64), newer: (u16, u64), newer_epoch: u64) -> Vec<u8> {
    let mut p = vec![0u8; TRANSFER_FEE_CONFIG_LEN];
    for (at, (bps, max)) in [
        (TRANSFER_FEE_OLDER_OFFSET, older),
        (TRANSFER_FEE_NEWER_OFFSET, newer),
    ] {
        p[at + TRANSFER_FEE_MAX_OFFSET..at + TRANSFER_FEE_MAX_OFFSET + 8]
            .copy_from_slice(&max.to_le_bytes());
        p[at + TRANSFER_FEE_BPS_OFFSET..at + TRANSFER_FEE_BPS_OFFSET + 2]
            .copy_from_slice(&bps.to_le_bytes());
    }
    let at = TRANSFER_FEE_NEWER_OFFSET + TRANSFER_FEE_EPOCH_OFFSET;
    p[at..at + 8].copy_from_slice(&newer_epoch.to_le_bytes());
    p
}

/// Zero older schedule, `newer` in force from epoch 0.
pub fn fee_config_payload(newer_bps: u16, newer_max: u64) -> Vec<u8> {
    fee_schedule_payload((0, 0), (newer_bps, newer_max), 0)
}

/// `TransferHook` payload with the given program id (`None` = dormant).
pub fn hook_payload(program: Option<Pubkey>) -> Vec<u8> {
    let mut p = vec![0u8; TRANSFER_HOOK_LEN];
    if let Some(program) = program {
        p[TRANSFER_HOOK_PROGRAM_ID_OFFSET..].copy_from_slice(program.as_ref());
    }
    p
}

/// An initialized Token-2022 mint account (no authorities, 0 decimals)
/// carrying `records` as its TLV trailer. For Mollusk runs that stop at the
/// mint policy, before any CPI.
pub fn mint_account(records: &[(u16, Vec<u8>)]) -> solana_account::Account {
    let mut data = vec![0u8; TOKEN_2022_BASE_MINT_LEN];
    data[45] = 1; // is_initialized
    if !records.is_empty() {
        data.resize(TOKEN_2022_TLV_START, 0);
        data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] = TOKEN_2022_ACCOUNT_TYPE_MINT;
        for (ty, payload) in records {
            data.extend_from_slice(&ty.to_le_bytes());
            data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            data.extend_from_slice(payload);
        }
    }
    solana_account::Account {
        lamports: 1_000_000,
        data,
        owner: TOKEN_2022,
        executable: false,
        rent_epoch: 0,
    }
}

/// `(label, mint account, expected error)` cases for the mint policy gate,
/// shared by the per-instruction Mollusk tests. `after_gate` is the error the
/// instruction hits next when the mint passes.
pub fn mint_policy_cases(
    after_gate: payment_channels::PaymentChannelsError,
) -> Vec<(
    &'static str,
    solana_account::Account,
    payment_channels::PaymentChannelsError,
)> {
    use payment_channels::PaymentChannelsError as E;
    let paxos = |fee: Vec<u8>, hook: Vec<u8>| {
        vec![
            (
                EXT_MINT_CLOSE_AUTHORITY,
                vec![1u8; MINT_CLOSE_AUTHORITY_LEN],
            ),
            (EXT_PERMANENT_DELEGATE, vec![1u8; PERMANENT_DELEGATE_LEN]),
            (EXT_TRANSFER_FEE_CONFIG, fee),
            (
                EXT_CONFIDENTIAL_TRANSFER_MINT,
                vec![0u8; CONFIDENTIAL_TRANSFER_MINT_LEN],
            ),
            (
                EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG,
                vec![0u8; CONFIDENTIAL_TRANSFER_FEE_CONFIG_LEN],
            ),
            (EXT_TRANSFER_HOOK, hook),
            (EXT_METADATA_POINTER, vec![0u8; POINTER_EXTENSION_LEN]),
        ]
    };
    vec![
        ("plain", mint_account(&[]), after_gate),
        (
            "paxos dormant",
            mint_account(&paxos(fee_config_payload(0, 0), hook_payload(None))),
            after_gate,
        ),
        (
            "live fee",
            mint_account(&paxos(fee_config_payload(10, 1_000), hook_payload(None))),
            E::ActiveMintTokenExtension,
        ),
        (
            // Issuer reverted an active fee at epoch 0: Token-2022 keeps
            // charging `older` until `newer` takes over at epoch 2, and
            // Mollusk's clock sits at epoch 0.
            "reverted fee still governed by older",
            mint_account(&paxos(
                fee_schedule_payload((10, 1_000), (0, 0), 2),
                hook_payload(None),
            )),
            E::ActiveMintTokenExtension,
        ),
        (
            "live hook",
            mint_account(&paxos(
                fee_config_payload(0, 0),
                hook_payload(Some(Pubkey::new_unique())),
            )),
            E::ActiveMintTokenExtension,
        ),
        (
            "non-transferable",
            mint_account(&[(EXT_NON_TRANSFERABLE, vec![])]),
            E::UnsupportedMintTokenExtensions,
        ),
        (
            "truncated fee config",
            mint_account(&[(EXT_TRANSFER_FEE_CONFIG, vec![0u8; 16])]),
            E::MalformedMintTokenExtensions,
        ),
    ]
}
