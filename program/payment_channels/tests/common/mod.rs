//! Shared harness for litesvm-driven end-to-end tests.

#![allow(dead_code)]

pub mod events;
pub mod lookup_table;
pub mod token_2022;
pub mod voucher;

use litesvm::LiteSVM;
use mollusk_svm::Mollusk;
use payment_channels::PaymentChannelsError;
use payment_channels::instructions::open::DISCRIMINATOR as OPEN_DISCRIMINATOR;
use payment_channels::state::Channel;
use payment_channels::state::channel::ChannelStatus;
use payment_channels::state::{AccountDiscriminator, CURRENT_CHANNEL_VERSION};
use pinocchio::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction, error::InstructionError};
use solana_keypair::Keypair;
use solana_pubkey::{Pubkey, pubkey};
use solana_signer::Signer;
use solana_transaction::Transaction;
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

/// `constants::TREASURY_OWNER` as a `Pubkey` — reads the program's single source of
/// truth, so tests track whatever the active build selects (default: localnet).
pub fn treasury_owner() -> Pubkey {
    Pubkey::new_from_array(*payment_channels::constants::TREASURY_OWNER.as_array())
}

pub fn token_balance(svm: &LiteSVM, account: &Pubkey) -> u64 {
    let acct = svm.get_account(account).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

pub fn set_clock(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = unix_timestamp;
    svm.set_sysvar::<Clock>(&clock);
}

/// Overwrites `Clock::slot`. LiteSVM leaves the slot at 0 by default; tests
/// that need to observe `open_slot` divergence across channel incarnations
/// advance it explicitly.
pub fn set_slot(svm: &mut LiteSVM, slot: u64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot = slot;
    svm.set_sysvar::<Clock>(&clock);
}

/// Opens a payment channel with a single 100% distribution recipient and
/// returns `(channel_pda, channel_ata)`.
#[allow(clippy::too_many_arguments)]
pub fn open_channel(
    svm: &mut LiteSVM,
    payer: &Keypair,
    payee: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    deposit: u64,
    mint: &Pubkey,
    payer_ata: &Pubkey,
    token_program: &Pubkey,
) -> (Pubkey, Pubkey) {
    let (channel, _) = Pubkey::find_program_address(
        &[
            b"channel",
            payer.pubkey().as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
        ],
        &PROGRAM_ID,
    );
    let (channel_ata, _) = Pubkey::find_program_address(
        &[channel.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );
    let event_auth = event_authority();

    let mut data: Vec<u8> = vec![OPEN_DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&3_600u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&[1u8; 32]);
    data.extend_from_slice(&5_000u16.to_le_bytes());

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(payer.pubkey(), true), // rent_payer (= payer)
            AccountMeta::new_readonly(*payee, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*authorized_signer, false),
            AccountMeta::new(channel, false),
            AccountMeta::new(*payer_ata, false),
            AccountMeta::new(channel_ata, false),
            AccountMeta::new_readonly(*token_program, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(SYSVAR_RENT, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(event_auth, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("open ok");

    (channel, channel_ata)
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

/// Read-only typed view over the `Channel` PDA blob managed by `svm`.
///
/// `Channel` is `#[repr(C)]` with `align_of::<Channel>() == 1` (every field
/// is `u8` / `[u8; N]` / `Address`), so casting a `&[u8]` of length
/// `Channel::LEN` to `&Channel` is sound. Same invariant the on-chain
/// `Transmutable` load relies on.
pub fn read_channel<R>(svm: &LiteSVM, channel: &Pubkey, f: impl FnOnce(&Channel) -> R) -> R {
    let acct = svm.get_account(channel).expect("channel exists");
    assert_eq!(
        acct.data.len(),
        Channel::LEN,
        "channel blob length mismatch"
    );
    let ch = unsafe { &*(acct.data.as_ptr() as *const Channel) };
    f(ch)
}

/// Typed mutator over the `Channel` PDA blob: get → mutate via setters /
/// field writes → set_account. Replaces hardcoded byte offsets so field
/// renames or type changes surface as compile errors.
pub fn mutate_channel<F: FnOnce(&mut Channel)>(svm: &mut LiteSVM, channel: &Pubkey, f: F) {
    let mut acct = svm.get_account(channel).expect("channel exists");
    assert_eq!(
        acct.data.len(),
        Channel::LEN,
        "channel blob length mismatch"
    );
    // SAFETY: see `read_channel`.
    let ch = unsafe { &mut *(acct.data.as_mut_ptr() as *mut Channel) };
    f(ch);
    svm.set_account(*channel, acct).expect("overwrite channel");
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
        // SAFETY: `Channel` is `#[repr(C)]` with `align_of == 1`; a zeroed
        // 216-byte `Vec<u8>` is a valid `Channel` for the purposes of
        // initializing every field below.
        let ch = unsafe { &mut *(data.as_mut_ptr() as *mut Channel) };
        ch.discriminator = AccountDiscriminator::Channel as u8;
        ch.version = CURRENT_CHANNEL_VERSION;
        ch.status = self.status as u8;
        ch.set_deposit(self.deposit);
        ch.set_settled(self.settled);
        ch.set_closure_started_at(self.closure_started_at);
        ch.set_payer_withdrawn_at(self.payer_withdrawn_at);
        ch.set_grace_period(self.grace_period);
        ch.payer = Address::new_from_array(self.payer.to_bytes());
        ch.payee = Address::new_from_array(self.payee.to_bytes());
        ch.authorized_signer = Address::new_from_array(self.authorized_signer.to_bytes());
        ch.mint = Address::new_from_array(self.mint.to_bytes());
        data
    }
}
