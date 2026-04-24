//! Shared harness for litesvm-driven end-to-end tests.

#![allow(dead_code)]

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use solana_instruction::error::InstructionError;
use solana_pubkey::Pubkey;
use solana_transaction_error::TransactionError;

pub const PROGRAM_ID: Pubkey = Pubkey::new_from_array(*payment_channels::ID.as_array());

pub fn load_program() -> LiteSVM {
    let mut svm = LiteSVM::new();
    let path = std::env::var("PAYMENT_CHANNELS_SO")
        .unwrap_or_else(|_| "../../target/deploy/payment_channels.so".into());
    svm.add_program_from_file(PROGRAM_ID, &path)
        .unwrap_or_else(|e| panic!("failed to load {path}: {e:?}"));
    svm
}

pub fn expect_custom_err(
    res: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    expected: PaymentChannelsError,
) {
    let err = res.expect_err("tx should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(code, expected as u32, "wrong custom error code");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
