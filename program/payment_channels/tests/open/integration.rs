use litesvm::LiteSVM;
use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::instructions::open::MAX_DISTRIBUTION_RECIPIENTS;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use super::{
    OpenRun, TOKEN_2022, derive_pdas, derive_pdas_with_token_program, open_ix,
    open_ix_with_token_program, setup_funded_svm, setup_funded_svm_with_token_program,
};
use crate::common::token_2022::mint_policy_cases;
use crate::common::token_2022::{
    CONFIDENTIAL_TRANSFER_FEE_CONFIG_LEN, CONFIDENTIAL_TRANSFER_MINT_LEN,
    EXT_CONFIDENTIAL_TRANSFER_ACCOUNT, EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG,
    EXT_CONFIDENTIAL_TRANSFER_MINT, EXT_CPI_GUARD, EXT_DEFAULT_ACCOUNT_STATE,
    EXT_GROUP_MEMBER_POINTER, EXT_GROUP_POINTER, EXT_IMMUTABLE_OWNER, EXT_MEMO_TRANSFER,
    EXT_METADATA_POINTER, EXT_MINT_CLOSE_AUTHORITY, EXT_NON_TRANSFERABLE, EXT_PAUSABLE,
    EXT_PERMANENT_DELEGATE, EXT_SCALED_UI_AMOUNT, EXT_TOKEN_GROUP, EXT_TOKEN_GROUP_MEMBER,
    EXT_TOKEN_METADATA, EXT_TRANSFER_FEE_AMOUNT, EXT_TRANSFER_FEE_CONFIG, EXT_TRANSFER_HOOK,
    EXT_TRANSFER_HOOK_ACCOUNT, MINT_CLOSE_AUTHORITY_LEN, PAUSABLE_LEN, PERMANENT_DELEGATE_LEN,
    POINTER_EXTENSION_LEN, SCALED_UI_AMOUNT_LEN, TOKEN_GROUP_LEN, TOKEN_GROUP_MEMBER_LEN,
    TOKEN_METADATA_MIN_LEN, TRANSFER_FEE_CONFIG_LEN, TRANSFER_FEE_NEWER_BPS_OFFSET,
    TRANSFER_FEE_NEWER_MAX_OFFSET, TRANSFER_HOOK_LEN, TRANSFER_HOOK_PROGRAM_ID_OFFSET,
    add_account_extension, add_malformed_mint_extension, add_mint_extension, extension_ids,
    patch_last_mint_extension, set_transfer_fee, set_transfer_hook_program,
    setup_paxos_style_funded_svm,
};
use crate::common::{PROGRAM_ID, ProgramLoader, SPL_TOKEN, expect_custom_err, token_balance};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3_600;

#[test]
fn zero_deposit_rejected() {
    assert_eq!(
        OpenRun::new(SALT, 0, GRACE, 1).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::DepositMustBeNonZero as u32
        )),
    );
}

#[test]
fn zero_grace_period_rejected() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, 0, 1).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::GracePeriodMustBeNonZero as u32
        )),
    );
}

#[test]
fn zero_recipients_passes_arg_validation() {
    // count == 0 is legal: the channel becomes a vanilla two-party channel
    // where the payee receives 100% of `pool` at `distribute`.
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, 0).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn too_many_recipients_rejected() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, MAX_DISTRIBUTION_RECIPIENTS as u8 + 1).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidRecipientCount as u32
        )),
    );
}

#[test]
fn single_recipient_passes_arg_validation() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, 1).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn max_recipients_passes_arg_validation() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, MAX_DISTRIBUTION_RECIPIENTS as u8).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn unsigned_payer_rejected() {
    assert_eq!(
        OpenRun {
            payer_is_signer: false,
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MissingRequiredSignature as u32
        )),
    );
}

#[test]
fn payer_equals_payee_rejected() {
    let same = Pubkey::new_unique();
    assert_eq!(
        OpenRun {
            payer: same,
            payee: same,
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::PayerPayeeMustDiffer as u32
        )),
    );
}

#[test]
fn wrong_channel_pda_rejected() {
    let payer = Pubkey::new_unique();
    let payee = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let wrong_channel = Pubkey::new_unique();
    assert_eq!(
        OpenRun {
            payer,
            payee,
            mint,
            authorized_signer,
            channel: wrong_channel,
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn off_curve_authorized_signer_rejected_before_mutation() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let (authorized_signer, _) =
        Pubkey::find_program_address(&[b"invalid-authorized-signer"], &PROGRAM_ID);
    let (payer, mint, payer_token_account) = setup_funded_svm(&mut svm, DEPOSIT);
    let (channel, channel_token_account) =
        derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT, 0);

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
        GRACE,
        0, // open_slot: fresh LiteSVM boots at slot 0
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::InvalidAuthorizedSigner,
    );
    assert!(svm.get_account(&channel).is_none());
    assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);
}

#[test]
fn bps_zero_rejected() {
    assert_eq!(
        OpenRun {
            recipients: Some(vec![(Pubkey::new_unique(), 0)]),
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidSplitConfig as u32
        )),
    );
}

#[test]
fn bps_sum_equals_10000_passes_arg_validation() {
    // Σ shareBps == 10_000 is legal under the payee-implicit-remainder model;
    // remainder is 0 and the payee receives no carve-out from `pool`.
    assert_eq!(
        OpenRun {
            recipients: Some(vec![
                (Pubkey::new_unique(), 5000),
                (Pubkey::new_unique(), 5000),
            ]),
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 2)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn bps_sum_above_10000_rejected() {
    assert_eq!(
        OpenRun {
            recipients: Some(vec![
                (Pubkey::new_unique(), 5000),
                (Pubkey::new_unique(), 5001),
            ]),
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 2)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidSplitConfig as u32
        )),
    );
}

#[test]
fn duplicate_recipient_rejected() {
    // `open` enforces uniqueness so `distribute` can trust the preimage
    // hash without rescanning the recipient list.
    let dup = Pubkey::new_unique();
    assert_eq!(
        OpenRun {
            recipients: Some(vec![(dup, 4000), (dup, 4000)]),
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 2)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::DuplicateRecipient as u32
        )),
    );
}

#[test]
fn channel_pda_recipient_rejected() {
    // Listing the channel PDA itself as a recipient is rejected at `open`
    // — the preimage-hash check at `distribute` would otherwise let dust
    // accumulate to a non-distributable address.
    let payer = Pubkey::new_unique();
    let payee = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (channel, channel_ata) = derive_pdas(&payer, &payee, &mint, &authorized_signer, SALT, 0);
    assert_eq!(
        OpenRun {
            payer,
            payee,
            mint,
            authorized_signer,
            channel,
            channel_ata,
            recipients: Some(vec![(channel, 5000)]),
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidSplitConfig as u32
        )),
    );
}

#[test]
fn non_ata_payer_token_account_rejected() {
    use litesvm_token::CreateAccount;

    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, _payer_ata) = setup_funded_svm(&mut svm, DEPOSIT);
    let (channel, channel_token_account) =
        derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT, 0);

    let non_ata = CreateAccount::new(&mut svm, &payer, &mint)
        .owner(&payer.pubkey())
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();

    let ix = open_ix(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &non_ata,
        &channel_token_account,
        SALT,
        DEPOSIT,
        GRACE,
        0, // open_slot: fresh LiteSVM boots at slot 0
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::PayerAccountMismatch,
    );
}

#[test]
fn token_2022_allowed_mint_extensions_succeed() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, payer_token_account) =
        setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
    for (extension_type, value_len) in [
        (EXT_METADATA_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_METADATA, TOKEN_METADATA_MIN_LEN),
        (EXT_GROUP_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP, TOKEN_GROUP_LEN),
        (EXT_GROUP_MEMBER_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP_MEMBER, TOKEN_GROUP_MEMBER_LEN),
        // Trusted / inert under the mint trust model.
        (EXT_MINT_CLOSE_AUTHORITY, MINT_CLOSE_AUTHORITY_LEN),
        (EXT_PERMANENT_DELEGATE, PERMANENT_DELEGATE_LEN),
        (
            EXT_CONFIDENTIAL_TRANSFER_MINT,
            CONFIDENTIAL_TRANSFER_MINT_LEN,
        ),
        (
            EXT_CONFIDENTIAL_TRANSFER_FEE_CONFIG,
            CONFIDENTIAL_TRANSFER_FEE_CONFIG_LEN,
        ),
        (EXT_PAUSABLE, PAUSABLE_LEN),
        (EXT_SCALED_UI_AMOUNT, SCALED_UI_AMOUNT_LEN),
        // State-gated, zero-filled == dormant (0 bps / 0 max; no hook program).
        (EXT_TRANSFER_FEE_CONFIG, TRANSFER_FEE_CONFIG_LEN),
        (EXT_TRANSFER_HOOK, TRANSFER_HOOK_LEN),
    ] {
        add_mint_extension(&mut svm, &mint, extension_type, value_len);
    }

    let (channel, channel_token_account) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        SALT,
        0, // open_slot seed: fresh LiteSVM boots at slot 0
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
        GRACE,
        0, // open_slot: fresh LiteSVM boots at slot 0
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx).expect("open should succeed");

    assert!(svm.get_account(&channel).is_some());
    assert_eq!(token_balance(&svm, &payer_token_account), 0);
    assert_eq!(token_balance(&svm, &channel_token_account), DEPOSIT);
}

#[test]
fn unsupported_token_2022_mint_extensions_reject_before_channel_creation() {
    for (extension_type, value_len) in [
        (EXT_NON_TRANSFERABLE, 0),
        (EXT_DEFAULT_ACCOUNT_STATE, 1),
        // Account-only records never belong on a mint.
        (EXT_CONFIDENTIAL_TRANSFER_ACCOUNT, 1),
        (EXT_MEMO_TRANSFER, 1),
    ] {
        let mut svm = LiteSVM::load_program();

        let payee = Pubkey::new_unique();
        let authorized_signer = Keypair::new().pubkey();
        let (payer, mint, payer_token_account) =
            setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
        add_mint_extension(&mut svm, &mint, extension_type, value_len);
        let (channel, channel_token_account) = derive_pdas_with_token_program(
            &payer.pubkey(),
            &payee,
            &mint,
            &authorized_signer,
            SALT,
            0, // open_slot seed: fresh LiteSVM boots at slot 0
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
            GRACE,
            0, // open_slot: fresh LiteSVM boots at slot 0
            1,
        );
        let msg = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
        expect_custom_err(
            svm.send_transaction(tx),
            PaymentChannelsError::UnsupportedMintTokenExtensions,
        );
        assert!(svm.get_account(&channel).is_none());
        assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);
    }
}

/// Spliced fee/hook records with live fields reject as active, not unsupported.
#[test]
fn live_token_2022_mint_extension_state_rejects_before_channel_creation() {
    // (type, len, offset within payload, bytes to patch in)
    let live_hook_program = Pubkey::new_unique().to_bytes();
    let cases: [(u16, usize, usize, &[u8]); 3] = [
        // newer fee: 10 bps, max 1_000
        (
            EXT_TRANSFER_FEE_CONFIG,
            TRANSFER_FEE_CONFIG_LEN,
            TRANSFER_FEE_NEWER_MAX_OFFSET,
            &[
                1_000u64.to_le_bytes().as_slice(),
                10u16.to_le_bytes().as_slice(),
            ]
            .concat(),
        ),
        // 10 bps with max 0 is still a zero fee (`calculate_fee`): accepted.
        (
            EXT_TRANSFER_FEE_CONFIG,
            TRANSFER_FEE_CONFIG_LEN,
            TRANSFER_FEE_NEWER_BPS_OFFSET,
            &10u16.to_le_bytes(),
        ),
        (
            EXT_TRANSFER_HOOK,
            TRANSFER_HOOK_LEN,
            TRANSFER_HOOK_PROGRAM_ID_OFFSET,
            &live_hook_program,
        ),
    ];
    for (i, (extension_type, value_len, offset, patch)) in cases.iter().enumerate() {
        let mut svm = LiteSVM::load_program();

        let payee = Pubkey::new_unique();
        let authorized_signer = Keypair::new().pubkey();
        let (payer, mint, payer_token_account) =
            setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
        add_mint_extension(&mut svm, &mint, *extension_type, *value_len);
        patch_last_mint_extension(&mut svm, &mint, *offset, patch);
        let (channel, channel_token_account) = derive_pdas_with_token_program(
            &payer.pubkey(),
            &payee,
            &mint,
            &authorized_signer,
            SALT,
            0, // open_slot seed: fresh LiteSVM boots at slot 0
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
            GRACE,
            0, // open_slot: fresh LiteSVM boots at slot 0
            1,
        );
        let msg = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
        let res = svm.send_transaction(tx);
        if i == 1 {
            res.expect("bps without a maximum fee cannot charge: dormant");
            assert!(svm.get_account(&channel).is_some());
        } else {
            expect_custom_err(res, PaymentChannelsError::ActiveMintTokenExtension);
            assert!(svm.get_account(&channel).is_none());
            assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);
        }
    }
}

fn open_paxos_style(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    payer_token_account: &Pubkey,
) -> (Pubkey, Pubkey, Result<(), PaymentChannelsError>) {
    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (channel, channel_token_account) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        mint,
        &authorized_signer,
        SALT,
        0,
        &TOKEN_2022,
    );
    let ix = open_ix_with_token_program(
        &payer.pubkey(),
        &payee,
        mint,
        &authorized_signer,
        &channel,
        payer_token_account,
        &channel_token_account,
        &TOKEN_2022,
        SALT,
        DEPOSIT,
        GRACE,
        0,
        1,
    );
    svm.expire_blockhash();
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, svm.latest_blockhash());
    let res = svm.send_transaction(tx).map(|_| ()).map_err(|e| {
        use solana_instruction::error::InstructionError;
        use solana_transaction_error::TransactionError;
        match e.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code)) => [
                PaymentChannelsError::UnsupportedMintTokenExtensions,
                PaymentChannelsError::ActiveMintTokenExtension,
                PaymentChannelsError::MalformedMintTokenExtensions,
            ]
            .into_iter()
            .find(|v| *v as u32 == code)
            .unwrap_or_else(|| panic!("unexpected custom error {code}")),
            other => panic!("unexpected error {other:?}"),
        }
    });
    (channel, channel_token_account, res)
}

/// Real Token-2022 program, PYUSD/USDG extension set: `open` succeeds and the
/// escrow ATA carries the three auto-added account extensions.
#[test]
fn token_2022_paxos_style_mint_opens_and_escrow_carries_auto_added_extensions() {
    let mut svm = LiteSVM::load_program();
    let (payer, mint, payer_token_account) = setup_paxos_style_funded_svm(&mut svm, DEPOSIT);

    let (channel, channel_token_account, res) =
        open_paxos_style(&mut svm, &payer, &mint, &payer_token_account);
    res.expect("paxos-style mint opens");

    assert!(svm.get_account(&channel).is_some());
    assert_eq!(token_balance(&svm, &payer_token_account), 0);
    assert_eq!(token_balance(&svm, &channel_token_account), DEPOSIT);

    let mut escrow_exts = extension_ids(&svm, &channel_token_account);
    escrow_exts.sort_unstable();
    assert_eq!(
        escrow_exts,
        vec![
            EXT_TRANSFER_FEE_AMOUNT,
            EXT_IMMUTABLE_OWNER,
            EXT_TRANSFER_HOOK_ACCOUNT
        ],
        "ATA program adds TransferFeeAmount + TransferHookAccount for a fee+hook mint"
    );
}

/// A scheduled fee or installed hook rejects `open` as active; clearing it
/// re-enables.
#[test]
fn token_2022_paxos_style_mint_live_fee_or_hook_rejects_open() {
    let mut svm = LiteSVM::load_program();
    let (payer, mint, payer_token_account) = setup_paxos_style_funded_svm(&mut svm, DEPOSIT);

    set_transfer_fee(&mut svm, &payer, &mint, 10, 1_000);
    let (channel, _, res) = open_paxos_style(&mut svm, &payer, &mint, &payer_token_account);
    assert_eq!(
        res.unwrap_err() as u32,
        PaymentChannelsError::ActiveMintTokenExtension as u32
    );
    assert!(svm.get_account(&channel).is_none());
    assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);

    set_transfer_fee(&mut svm, &payer, &mint, 0, 0);
    set_transfer_hook_program(&mut svm, &payer, &mint, Some(Pubkey::new_unique()));
    let (channel, _, res) = open_paxos_style(&mut svm, &payer, &mint, &payer_token_account);
    assert_eq!(
        res.unwrap_err() as u32,
        PaymentChannelsError::ActiveMintTokenExtension as u32
    );
    assert!(svm.get_account(&channel).is_none());

    set_transfer_hook_program(&mut svm, &payer, &mint, None);
    let (channel, channel_token_account, res) =
        open_paxos_style(&mut svm, &payer, &mint, &payer_token_account);
    res.expect("dormant again");
    assert!(svm.get_account(&channel).is_some());
    assert_eq!(token_balance(&svm, &channel_token_account), DEPOSIT);
}

#[test]
fn malformed_token_2022_mint_extensions_reject_before_channel_creation() {
    let mut svm = LiteSVM::load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Keypair::new().pubkey();
    let (payer, mint, payer_token_account) =
        setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
    add_malformed_mint_extension(&mut svm, &mint, EXT_METADATA_POINTER, POINTER_EXTENSION_LEN);
    let (channel, channel_token_account) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        SALT,
        0,
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
        GRACE,
        0,
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::MalformedMintTokenExtensions,
    );
    assert!(svm.get_account(&channel).is_none());
    assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);
}

#[test]
fn unsupported_token_2022_payer_account_extensions_reject_before_channel_creation() {
    for extension_type in [EXT_MEMO_TRANSFER, EXT_CPI_GUARD] {
        let mut svm = LiteSVM::load_program();

        let payee = Pubkey::new_unique();
        let authorized_signer = Keypair::new().pubkey();
        let (payer, mint, payer_token_account) =
            setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
        add_account_extension(&mut svm, &payer_token_account, extension_type, 1);
        let (channel, channel_token_account) = derive_pdas_with_token_program(
            &payer.pubkey(),
            &payee,
            &mint,
            &authorized_signer,
            SALT,
            0, // open_slot seed: fresh LiteSVM boots at slot 0
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
            GRACE,
            0, // open_slot: fresh LiteSVM boots at slot 0
            1,
        );
        let msg = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
        expect_custom_err(
            svm.send_transaction(tx),
            PaymentChannelsError::InvalidPayerTokenExtensions,
        );
        assert!(svm.get_account(&channel).is_none());
        assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);
    }
}

/// The exact-slice destructure rejects extra accounts (surfaced as the
/// builtin NotEnoughAccountKeys, despite the too-many direction).
#[test]
fn extra_account_rejects() {
    assert_eq!(
        OpenRun {
            extra_accounts: vec![solana_instruction::AccountMeta::new_readonly(
                Pubkey::new_unique(),
                false
            )],
            ..OpenRun::new(1, 100, 60, 0)
        }
        .run(),
        ProgramResult::Failure(ProgramError::NotEnoughAccountKeys),
    );
}

/// Mint policy runs right after the channel-address check and before any
/// CPI: a passing mint falls through to the escrow-ATA check, a live or
/// unsupported one stops here.
#[test]
fn token_2022_mint_policy_gate_runs_before_any_cpi() {
    for (label, mint_account, expected) in
        mint_policy_cases(PaymentChannelsError::ChannelAccountMismatch)
    {
        let mut run = OpenRun::new(SALT, DEPOSIT, GRACE, 1);
        let mint = Pubkey::new_unique();
        let (channel, _) = derive_pdas_with_token_program(
            &run.payer,
            &run.payee,
            &mint,
            &run.authorized_signer,
            SALT,
            0,
            &TOKEN_2022,
        );
        run.mint = mint;
        run.channel = channel;
        run.token_program = TOKEN_2022;
        run.mint_account = Some(mint_account);
        assert_eq!(
            run.run(),
            ProgramResult::Failure(ProgramError::Custom(expected as u32)),
            "{label}"
        );
    }
}
