mod e2e;
mod integration;

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels_core::{
    event_engine::event_authority_pda,
    instructions::open::{DISCRIMINATOR, MAX_DISTRIBUTION_RECIPIENTS},
    state::Channel,
};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::common::{
    ATA_PROGRAM, PROGRAM_ID, ProgramLoader, SPL_TOKEN, SYSTEM_PROGRAM, SYSVAR_RENT, TOKEN_2022,
};

pub(super) const EVENT_AUTHORITY: Pubkey =
    Pubkey::new_from_array(*event_authority_pda::ID.as_array());

/// Wire-format width per `DistributionEntry`: 32 bytes pubkey + u16 bps.
const ENTRY_LEN: usize = 32 + 2;

/// Execution descriptor for a single `open` Mollusk run.
///
/// Construct with [`OpenRun::new`] for the arg fields; override any public
/// field via struct update syntax before calling [`OpenRun::run`].
pub(super) struct OpenRun {
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub num_recipients: u8,
    pub payer: Pubkey,
    pub payer_is_signer: bool,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    /// Defaults to a random pubkey, causing `ChannelAddressMismatch`.
    pub channel: Pubkey,
    /// Defaults to a random pubkey.
    pub channel_ata: Pubkey,
    /// When `Some`, these `(recipient, bps)` pairs replace the synthetic
    /// `[(i+1, i+1)]` defaults — let bps-validation and duplicate-recipient
    /// tests drive arbitrary entry payloads through the same builder.
    pub recipients: Option<Vec<(Pubkey, u16)>>,
}

impl OpenRun {
    pub fn new(salt: u64, deposit: u64, grace_period: u32, num_recipients: u8) -> Self {
        Self {
            salt,
            deposit,
            grace_period,
            num_recipients,
            payer: Pubkey::new_unique(),
            payer_is_signer: true,
            payee: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            authorized_signer: Pubkey::new_unique(),
            channel: Pubkey::new_unique(),
            channel_ata: Pubkey::new_unique(),
            recipients: None,
        }
    }

    pub fn run(self) -> ProgramResult {
        let mollusk = Mollusk::load_program();

        let mut data = vec![DISCRIMINATOR];
        data.extend_from_slice(&self.salt.to_le_bytes());
        data.extend_from_slice(&self.deposit.to_le_bytes());
        data.extend_from_slice(&self.grace_period.to_le_bytes());
        data.push(self.num_recipients);
        for i in 0..MAX_DISTRIBUTION_RECIPIENTS {
            let active = (i as u8) < self.num_recipients;
            if active {
                let (pk, bps) = match &self.recipients {
                    Some(rs) => rs[i],
                    None => (Pubkey::new_from_array([i as u8 + 1; 32]), i as u16 + 1),
                };
                data.extend_from_slice(pk.as_ref());
                data.extend_from_slice(&bps.to_le_bytes());
            } else {
                data.extend_from_slice(&[0u8; ENTRY_LEN]);
            }
        }

        let ix = Instruction::new_with_bytes(
            PROGRAM_ID,
            &data,
            vec![
                AccountMeta::new(self.payer, self.payer_is_signer),
                AccountMeta::new_readonly(self.payee, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new_readonly(self.authorized_signer, false),
                AccountMeta::new(self.channel, false),
                AccountMeta::new(Pubkey::new_unique(), false), // payer_token_account
                AccountMeta::new(self.channel_ata, false),
                AccountMeta::new_readonly(SPL_TOKEN, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(SYSVAR_RENT, false),
                AccountMeta::new_readonly(ATA_PROGRAM, false),
                AccountMeta::new_readonly(EVENT_AUTHORITY, false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
        );

        let dummy = Account {
            lamports: 1_000_000,
            ..Default::default()
        };
        // Channel account needs Channel::LEN bytes so the program can write
        // into it after the address checks pass (reached only in escrow test).
        let channel_account = Account {
            lamports: 1_000_000,
            data: vec![0u8; Channel::LEN],
            ..Default::default()
        };

        let accounts: Vec<(Pubkey, Account)> = ix
            .accounts
            .iter()
            .filter(|m| m.pubkey != PROGRAM_ID)
            .map(|m| {
                let acc = if m.pubkey == self.channel {
                    channel_account.clone()
                } else {
                    dummy.clone()
                };
                (m.pubkey, acc)
            })
            .collect();

        mollusk.process_instruction(&ix, &accounts).program_result
    }
}

/// Airdrop, create mint, mint `deposit` tokens to payer's ATA (SPL Token).
pub(super) fn setup_funded_svm(svm: &mut LiteSVM, deposit: u64) -> (Keypair, Pubkey, Pubkey) {
    setup_funded_svm_with_token_program(svm, deposit, &SPL_TOKEN)
}

/// Airdrop, create mint, mint `deposit` tokens to payer's ATA under
/// `token_program`. Returns `(payer_keypair, mint, payer_token_account)`.
pub(crate) fn setup_funded_svm_with_token_program(
    svm: &mut LiteSVM,
    deposit: u64,
    token_program: &Pubkey,
) -> (Keypair, Pubkey, Pubkey) {
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let mint = CreateMint::new(svm, &payer)
        .decimals(0)
        .token_program_id(token_program)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(svm, &payer, &mint)
        .token_program_id(token_program)
        .send()
        .unwrap();
    MintTo::new(svm, &payer, &mint, &payer_ata, deposit)
        .token_program_id(token_program)
        .send()
        .unwrap();
    (payer, mint, payer_ata)
}

/// Derive `(channel_pda, channel_ata)` for the given seeds.
pub(super) fn derive_pdas(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
) -> (Pubkey, Pubkey) {
    let (channel, _) = Pubkey::find_program_address(
        &[
            b"channel",
            payer.as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
        ],
        &PROGRAM_ID,
    );
    let (ata, _) = Pubkey::find_program_address(
        &[channel.as_ref(), SPL_TOKEN.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );
    (channel, ata)
}

/// Build the `open` instruction with all 13 accounts wired up.
///
/// Wire layout: `discriminator(1) | salt(8) | deposit(8) | grace(4) |
/// num_recipients(1) | entries(MAX × 34)` where each entry is `pubkey(32) | bps(u16)`.
#[allow(clippy::too_many_arguments)]
pub(super) fn open_ix(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    channel: &Pubkey,
    payer_token_account: &Pubkey,
    channel_token_account: &Pubkey,
    salt: u64,
    deposit: u64,
    grace_period: u32,
    num_recipients: u8,
) -> Instruction {
    open_ix_with_token_program(
        payer,
        payee,
        mint,
        authorized_signer,
        channel,
        payer_token_account,
        channel_token_account,
        &SPL_TOKEN,
        salt,
        deposit,
        grace_period,
        num_recipients,
    )
}

/// `open_ix` parameterized over the token program (SPL Token vs Token-2022).
#[allow(clippy::too_many_arguments)]
pub(super) fn open_ix_with_token_program(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    channel: &Pubkey,
    payer_token_account: &Pubkey,
    channel_token_account: &Pubkey,
    token_program: &Pubkey,
    salt: u64,
    deposit: u64,
    grace_period: u32,
    num_recipients: u8,
) -> Instruction {
    let mut data = vec![DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&grace_period.to_le_bytes());
    data.push(num_recipients);
    for i in 0..MAX_DISTRIBUTION_RECIPIENTS {
        if (i as u8) < num_recipients {
            data.extend_from_slice(&[i as u8 + 1; 32]);
            data.extend_from_slice(&(i as u16 + 1).to_le_bytes());
        } else {
            data.extend_from_slice(&[0u8; ENTRY_LEN]);
        }
    }
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*payee, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*authorized_signer, false),
            AccountMeta::new(*channel, false),
            AccountMeta::new(*payer_token_account, false),
            AccountMeta::new(*channel_token_account, false),
            AccountMeta::new_readonly(*token_program, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(SYSVAR_RENT, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(EVENT_AUTHORITY, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    )
}

/// Derive `(channel_pda, channel_ata)` parameterized over token program.
pub(super) fn derive_pdas_with_token_program(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    token_program: &Pubkey,
) -> (Pubkey, Pubkey) {
    let (channel, _) = Pubkey::find_program_address(
        &[
            b"channel",
            payer.as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
        ],
        &PROGRAM_ID,
    );
    let (ata, _) = Pubkey::find_program_address(
        &[channel.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );
    (channel, ata)
}
