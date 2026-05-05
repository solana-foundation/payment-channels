//! Shared harness for litesvm-driven end-to-end tests.

#![allow(dead_code)]

pub mod token_2022;

use litesvm::LiteSVM;
use mollusk_svm::Mollusk;
use payment_channels::PaymentChannelsError;
use payment_channels::state::Channel;
use payment_channels::state::channel::ChannelStatus;
use solana_instruction::{Instruction, error::InstructionError};
use solana_pubkey::{Pubkey, pubkey};
use solana_transaction_error::TransactionError;

/// Payment channels program ID.
pub const PROGRAM_ID: Pubkey = Pubkey::new_from_array(*payment_channels::ID.as_array());

pub const SPL_TOKEN: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
pub const SYSVAR_RENT: Pubkey = pubkey!("SysvarRent111111111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR: Pubkey = pubkey!("Sysvar1nstructions1111111111111111111111111");

pub fn ed25519_program_id() -> Pubkey {
    Pubkey::new_from_array(*payment_channels::ed25519::PROGRAM_ID.as_array())
}

pub fn event_authority() -> Pubkey {
    Pubkey::find_program_address(
        &[payment_channels::event_engine::EVENT_AUTHORITY_SEED],
        &PROGRAM_ID,
    )
    .0
}

pub fn token_balance(svm: &LiteSVM, account: &Pubkey) -> u64 {
    let acct = svm.get_account(account).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

/// `ComputeBudgetInstruction::SetComputeUnitLimit(u32)` — variant tag 2
/// followed by the limit as little-endian `u32`. Used as a stand-in for
/// a non-Ed25519 preceding ix.
pub fn compute_budget_ix(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(0x02);
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: pubkey!("ComputeBudget111111111111111111111111111111"),
        accounts: Vec::new(),
        data,
    }
}

fn program_binary_path() -> String {
    std::env::var("PAYMENT_CHANNELS_SO")
        .unwrap_or_else(|_| "../../target/deploy/payment_channels.so".into())
}

/// Program loader trait for LiteSVM and Mollusk runtimes.
pub trait ProgramLoader: Sized {
    fn load_program_at(path: &str) -> Self;

    fn load_program() -> Self {
        Self::load_program_at(&program_binary_path())
    }
}

impl ProgramLoader for LiteSVM {
    fn load_program_at(path: &str) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(PROGRAM_ID, path)
            .unwrap_or_else(|e| panic!("failed to load {path}: {e:?}"));
        svm
    }
}

impl ProgramLoader for Mollusk {
    fn load_program_at(path: &str) -> Self {
        let elf = mollusk_svm::file::read_file(path);
        let mut m = Mollusk::default();
        m.add_program_with_loader_and_elf(
            &PROGRAM_ID,
            &mollusk_svm::program::loader_keys::LOADER_V3,
            &elf,
        );
        m
    }
}

/// Assert a LiteSVM transaction result failed with the expected custom error.
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

/// Assert a LiteSVM transaction result failed with the expected builtin
/// `InstructionError` variant. Sibling to [`expect_custom_err`] for failure
/// modes that surface as builtin variants (e.g., `InvalidAccountData`,
/// `MissingRequiredSignature`) rather than `Custom(code)`.
pub fn expect_instruction_err(
    res: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    expected: InstructionError,
) {
    let err = res.expect_err("tx should fail");
    match err.err {
        TransactionError::InstructionError(_, ix_err) => {
            assert_eq!(ix_err, expected, "wrong InstructionError variant");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Builds a [`Channel`] account blob for use in Mollusk integration tests.
pub struct ChannelBuilder {
    status: ChannelStatus,
    deposit: u64,
    settled: u64,
    closure_started_at: i64,
    payer_withdrawn_at: i64,
    grace_period: u32,
    payer: Pubkey,
    payee: Pubkey,
    authorized_signer: Pubkey,
    mint: Pubkey,
}

impl ChannelBuilder {
    pub fn new() -> Self {
        Self {
            status: ChannelStatus::Open,
            deposit: 0,
            settled: 0,
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: 0,
            payer: Pubkey::default(),
            payee: Pubkey::default(),
            authorized_signer: Pubkey::default(),
            mint: Pubkey::default(),
        }
    }

    pub fn status(mut self, status: ChannelStatus) -> Self {
        self.status = status;
        self
    }

    pub fn deposit(mut self, deposit: u64) -> Self {
        self.deposit = deposit;
        self
    }

    pub fn settled(mut self, settled: u64) -> Self {
        self.settled = settled;
        self
    }

    pub fn closure_started_at(mut self, v: i64) -> Self {
        self.closure_started_at = v;
        self
    }

    pub fn payer_withdrawn_at(mut self, v: i64) -> Self {
        self.payer_withdrawn_at = v;
        self
    }

    pub fn grace_period(mut self, v: u32) -> Self {
        self.grace_period = v;
        self
    }

    pub fn payer(mut self, payer: Pubkey) -> Self {
        self.payer = payer;
        self
    }

    pub fn payee(mut self, payee: Pubkey) -> Self {
        self.payee = payee;
        self
    }

    pub fn authorized_signer(mut self, authorized_signer: Pubkey) -> Self {
        self.authorized_signer = authorized_signer;
        self
    }

    pub fn mint(mut self, mint: Pubkey) -> Self {
        self.mint = mint;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut data = vec![0u8; Channel::LEN];
        data[0] = 1; // AccountDiscriminator::Channel
        data[1] = 1; // CURRENT_CHANNEL_VERSION
        data[3] = self.status as u8;
        data[12..20].copy_from_slice(&self.deposit.to_le_bytes());
        data[20..28].copy_from_slice(&self.settled.to_le_bytes());
        data[36..44].copy_from_slice(&self.closure_started_at.to_le_bytes());
        data[44..52].copy_from_slice(&self.payer_withdrawn_at.to_le_bytes());
        data[52..56].copy_from_slice(&self.grace_period.to_le_bytes());
        data[88..120].copy_from_slice(&self.payer.to_bytes());
        data[120..152].copy_from_slice(&self.payee.to_bytes());
        data[152..184].copy_from_slice(&self.authorized_signer.to_bytes());
        data[184..216].copy_from_slice(&self.mint.to_bytes());
        data
    }
}
