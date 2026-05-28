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
use crate::common::token_2022::{
    EXT_CPI_GUARD, EXT_GROUP_MEMBER_POINTER, EXT_GROUP_POINTER, EXT_MEMO_TRANSFER,
    EXT_METADATA_POINTER, EXT_MINT_CLOSE_AUTHORITY, EXT_TOKEN_GROUP, EXT_TOKEN_GROUP_MEMBER,
    EXT_TOKEN_METADATA, EXT_TRANSFER_FEE_CONFIG, EXT_TRANSFER_HOOK, POINTER_EXTENSION_LEN,
    TOKEN_GROUP_LEN, TOKEN_GROUP_MEMBER_LEN, TOKEN_METADATA_MIN_LEN, add_account_extension,
    add_mint_extension,
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
        GRACE,
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
    let (channel, channel_ata) = derive_pdas(&payer, &payee, &mint, &authorized_signer, SALT);
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
        derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT);

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
    ] {
        add_mint_extension(&mut svm, &mint, extension_type, value_len);
    }

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
        GRACE,
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
        (EXT_TRANSFER_FEE_CONFIG, 108),
        (EXT_TRANSFER_HOOK, 64),
        (EXT_MINT_CLOSE_AUTHORITY, 32),
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
