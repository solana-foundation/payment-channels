//! Real SBF channel -> SBF callback integration, deliberately independent of generated V2 clients.
#![allow(clippy::result_large_err)]

mod common;
use common::*;
use litesvm::{
    LiteSVM,
    types::{FailedTransactionMetadata, TransactionMetadata},
};
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction, error::InstructionError};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const ADAPTER: Pubkey = Pubkey::new_from_array([77; 32]);
fn ro(key: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}
fn rw(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, false)
}
fn ata(owner: Pubkey, mint: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), SPL_TOKEN.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    )
    .0
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_hooked_channel<R>(
    svm: &LiteSVM,
    channel: &Pubkey,
    f: impl FnOnce(&payment_channels::ChannelWithHooks) -> R,
) -> R {
    let account = svm.get_account(channel).expect("channel exists");
    f(payment_channels::ChannelWithHooks::from_bytes(&account.data).expect("hooked channel"))
}

fn mutate_hooked_channel(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    f: impl FnOnce(&mut payment_channels::ChannelWithHooks),
) {
    let mut account = svm.get_account(channel).expect("channel exists");
    f(
        payment_channels::ChannelWithHooks::from_bytes_mut(&mut account.data)
            .expect("hooked channel"),
    );
    svm.set_account(*channel, account)
        .expect("overwrite channel");
}

fn add_v3_program(svm: &mut LiteSVM, program_id: Pubkey, path: &std::path::Path) {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    assert!(
        bytes.len() >= 64 && &bytes[..7] == b"\x7fELF\x02\x01\x01",
        "{} must be a 64-bit little-endian ELF",
        path.display()
    );
    // ELF64 e_flags identifies the SBPF ISA. Reject stale v0 artifacts rather
    // than accidentally testing a different compiler target.
    assert_eq!(
        u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
        3,
        "{} must be compiled with --arch v3",
        path.display()
    );
    svm.add_program(program_id, &bytes).unwrap();
}

struct Fixture {
    svm: LiteSVM,
    payer: Keypair,
    stranger: Keypair,
    mint: Pubkey,
    payer_ata: Pubkey,
    payee: Pubkey,
    payee_ata: Pubkey,
    treasury_ata: Pubkey,
    channel: Pubkey,
    escrow: Pubkey,
    recorder: Pubkey,
    config: Vec<u8>,
    phases: Vec<usize>,
    commitment: [u8; 32],
    extras: Vec<Pubkey>,
}
impl Fixture {
    fn new(phases: &[usize]) -> Self {
        Self::with_mode(phases, 0)
    }
    fn with_mode(phases: &[usize], mode: u8) -> Self {
        let mut svm = LiteSVM::new();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let program_path = std::env::var_os("PAYMENT_CHANNELS_V2_SO")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| root.join("target/deploy-v2/payment_channels.so"));
        add_v3_program(&mut svm, PROGRAM_ID, &program_path);
        add_v3_program(
            &mut svm,
            ADAPTER,
            &root.join("target/deploy-v2/hook_test_adapter.so"),
        );
        let payer = Keypair::new();
        let stranger = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
        let mint = CreateMint::new(&mut svm, &payer)
            .token_program_id(&SPL_TOKEN)
            .decimals(0)
            .send()
            .unwrap();
        let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
            .token_program_id(&SPL_TOKEN)
            .send()
            .unwrap();
        MintTo::new(&mut svm, &payer, &mint, &payer_ata, 10_000)
            .token_program_id(&SPL_TOKEN)
            .send()
            .unwrap();
        let payee = Pubkey::new_unique();
        let payee_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
            .token_program_id(&SPL_TOKEN)
            .owner(&payee)
            .send()
            .unwrap();
        let treasury_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
            .token_program_id(&SPL_TOKEN)
            .owner(&treasury_owner())
            .send()
            .unwrap();
        let channel = Pubkey::find_program_address(
            &[
                b"channel",
                payer.pubkey().as_ref(),
                payee.as_ref(),
                mint.as_ref(),
                payer.pubkey().as_ref(),
                &1u64.to_le_bytes(),
                &0u64.to_le_bytes(),
            ],
            &PROGRAM_ID,
        )
        .0;
        let escrow = ata(channel, mint);
        let recorder = Pubkey::new_unique();
        let mut record_data = vec![0; 8 + 428 * 16];
        record_data[2] = mode;
        svm.set_account(
            recorder,
            Account {
                lamports: 100_000_000,
                data: record_data,
                owner: ADAPTER,
                ..Account::default()
            },
        )
        .unwrap();
        let mut extras = vec![payer.pubkey()];
        if mode == 1 {
            extras.push(PROGRAM_ID);
        }
        if mode == 2 {
            extras.extend([SPL_TOKEN, mint]);
        }
        let mut config = vec![];
        let mut fixed = [0u8; 824];
        for phase in 0..4 {
            if !phases.contains(&phase) {
                config.push(0);
                continue;
            }
            let slot = &mut fixed[phase * 206..(phase + 1) * 206];
            slot[..32].copy_from_slice(ADAPTER.as_ref());
            slot[32..40].copy_from_slice(b"record!!");
            slot[40] = 1 + extras.len() as u8;
            slot[74..106].copy_from_slice(recorder.as_ref());
            slot[106] = 1;
            for (i, key) in extras.iter().enumerate() {
                slot[107 + i * 33..139 + i * 33].copy_from_slice(key.as_ref());
            }
            config.push(1);
            config.extend_from_slice(ADAPTER.as_ref());
            config.extend_from_slice(b"record!!");
            config.extend_from_slice(&[1 + extras.len() as u8, 0]);
            config.extend_from_slice(recorder.as_ref());
            config.push(1);
            // A real transaction signer appears as an extra, but must NOT sign in CPI.
            for key in &extras {
                config.extend_from_slice(key.as_ref());
                config.push(0);
            }
        }
        let commitment = const_crypto::sha2::Sha256::new().update(&fixed).finalize();
        Self {
            svm,
            payer,
            stranger,
            mint,
            payer_ata,
            payee,
            payee_ata,
            treasury_ata,
            channel,
            escrow,
            recorder,
            config,
            phases: phases.to_vec(),
            commitment,
            extras,
        }
    }
    fn tail(&self, first: usize) -> Vec<AccountMeta> {
        let mut metas = vec![];
        for phase in first..first + 2 {
            if !self.phases.contains(&phase) {
                continue;
            }
            let authority = Pubkey::find_program_address(
                &[
                    b"channel_hook",
                    self.channel.as_ref(),
                    &self.commitment,
                    &[phase as u8],
                    ADAPTER.as_ref(),
                ],
                &PROGRAM_ID,
            )
            .0;
            metas.extend([ro(ADAPTER), ro(authority), rw(self.recorder)]);
            metas.extend(self.extras.iter().copied().map(ro));
        }
        metas
    }
    fn open_ix(&self) -> Instruction {
        let mut data = vec![10];
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&1_000u64.to_le_bytes());
        data.extend_from_slice(&3_600u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(self.payee.as_ref());
        data.extend_from_slice(&10_000u16.to_le_bytes());
        data.extend_from_slice(&self.config);
        let mut accounts = vec![
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new(self.payer.pubkey(), true),
            ro(self.payee),
            ro(self.mint),
            ro(self.payer.pubkey()),
            rw(self.channel),
            rw(self.payer_ata),
            rw(self.escrow),
            ro(SPL_TOKEN),
            ro(SYSTEM_PROGRAM),
            ro(SYSVAR_RENT),
            ro(ATA_PROGRAM),
            ro(event_authority()),
            ro(PROGRAM_ID),
        ];
        accounts.extend(self.tail(0));
        Instruction {
            program_id: PROGRAM_ID,
            accounts,
            data,
        }
    }
    fn operation(&self, op: u8) -> Instruction {
        // Callback operation tags retain the original economic instruction IDs.
        let mut data = vec![match op {
            3 => 11,
            7 => 12,
            8 => 13,
            _ => unreachable!(),
        }];
        let mut accounts = match op {
            3 => {
                data.extend_from_slice(&200u64.to_le_bytes());
                vec![
                    AccountMeta::new(self.payer.pubkey(), true),
                    rw(self.channel),
                    rw(self.payer_ata),
                    rw(self.escrow),
                    ro(self.mint),
                    ro(SPL_TOKEN),
                ]
            }
            8 => vec![
                AccountMeta::new(self.payer.pubkey(), true),
                rw(self.channel),
                rw(self.escrow),
                rw(self.payer_ata),
                ro(self.mint),
                ro(SPL_TOKEN),
            ],
            7 => {
                data.extend_from_slice(&1u32.to_le_bytes());
                data.extend_from_slice(self.payee.as_ref());
                data.extend_from_slice(&10_000u16.to_le_bytes());
                vec![
                    rw(self.channel),
                    rw(self.payer.pubkey()),
                    rw(self.payer.pubkey()),
                    rw(self.escrow),
                    rw(self.payer_ata),
                    rw(self.payee_ata),
                    rw(self.treasury_ata),
                    ro(self.mint),
                    ro(SPL_TOKEN),
                    ro(event_authority()),
                    ro(PROGRAM_ID),
                    rw(self.payee_ata),
                ]
            }
            _ => unreachable!(),
        };
        accounts.extend(self.tail(if op == 3 { 0 } else { 2 }));
        Instruction {
            program_id: PROGRAM_ID,
            accounts,
            data,
        }
    }
    fn send(&mut self, ix: Instruction) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        // Permissionless distribute pays fees with an unrelated signer.
        let operation = ix.data[0];
        let signer = if matches!(ix.data[0], 7 | 12) {
            &self.stranger
        } else {
            &self.payer
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&signer.pubkey()),
            &[signer],
            self.svm.latest_blockhash(),
        );
        let packet = 1 + tx.signatures.len() * 64 + tx.message.serialize().len();
        assert!(packet <= 1232, "oversized transaction: {packet}");
        let result = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        if let Ok(meta) = &result {
            eprintln!(
                "op {operation}, phases {:?}: {packet} bytes, {} CU",
                self.phases, meta.compute_units_consumed
            );
        }
        result
    }
    fn open(&mut self) {
        let ix = self.open_ix();
        self.send(ix).unwrap();
    }
    fn records(&self) -> Vec<Vec<u8>> {
        let a = self.svm.get_account(&self.recorder).unwrap();
        (0..a.data[1] as usize)
            .map(|i| a.data[8 + i * 428..8 + (i + 1) * 428].to_vec())
            .collect()
    }
    fn fail(&mut self, phase: u8) {
        let mut a = self.svm.get_account(&self.recorder).unwrap();
        a.data[0] = phase + 1;
        self.svm.set_account(self.recorder, a).unwrap();
    }
    fn accounting(&mut self, settled: u64, sealed: bool) {
        // State setup only: the operation under test and every hook execute SBF.
        mutate_hooked_channel(&mut self.svm, &self.channel, |ch| {
            ch.set_settled(settled);
            ch.status = if sealed { 1 } else { 0 };
        });
    }
    fn snapshot(&self) -> Vec<Option<Account>> {
        [
            self.channel,
            self.escrow,
            self.payer_ata,
            self.payee_ata,
            self.treasury_ata,
            self.recorder,
        ]
        .iter()
        .map(|k| self.svm.get_account(k))
        .collect()
    }
    fn assert_pair(&self, operation: u8, sequence: u64) {
        let records = self.records();
        let pair = &records[records.len() - 2..];
        for (i, context) in pair.iter().enumerate() {
            assert_eq!(context[2], operation);
            assert_eq!(context[3], i as u8);
            assert_eq!(u64_at(context, 36), sequence);
            assert_eq!(&context[180..212], &self.commitment);
            assert_eq!(&context[396..428], self.payer_ata.as_ref());
        }
        assert_eq!(pair[1][1], pair[0][1] + 1);
        for offset in [332, 340, 348, 356, 364] {
            assert_eq!(u64_at(&pair[0], offset), 0, "pre callback transfers");
        }
        for (before, after) in [(276, 372), (292, 380), (300, 388)] {
            assert_eq!(u64_at(&pair[0], before), u64_at(&pair[0], after));
        }
        assert_eq!(
            u64_at(&pair[1], 372),
            u64_at(&pair[1], 276) + u64_at(&pair[1], 332)
        );
    }
}

#[test]
fn sbf_original_instructions_reject_hooked_channels_without_side_effects() {
    for op in [1, 3, 7, 8] {
        let mut f = Fixture::new(if op <= 3 { &[0, 1] } else { &[2, 3] });
        f.open();
        if op >= 7 {
            f.accounting(400, true);
        }
        let mut ix = if op == 1 {
            f.open_ix()
        } else {
            f.operation(op)
        };
        ix.data[0] = op;
        // Use the original ABI, not a malformed instruction or a missing tail.
        if op == 1 {
            ix.data.truncate(67);
        }
        ix.accounts.truncate(match op {
            1 => 14,
            7 => 12,
            _ => 6,
        });
        let before = f.snapshot();
        assert!(f.send(ix).is_err(), "original operation {op} accepted V2");
        assert_eq!(f.snapshot(), before, "original operation {op}");
    }
}

#[test]
fn sbf_hooked_instructions_reject_v1_channels_without_side_effects() {
    for op in [1, 3, 7, 8] {
        let mut f = Fixture::new(&[]);
        let mut open = f.open_ix();
        open.data[0] = 1;
        open.data.truncate(67);
        f.send(open).unwrap();
        assert_eq!(f.svm.get_account(&f.channel).unwrap().data.len(), 256);
        // V1 remains operational in the very same SBF runtime.
        let mut top_up = f.operation(3);
        top_up.data[0] = 3;
        f.send(top_up).unwrap();
        assert_eq!(token_balance(&f.svm, &f.escrow), 1_200);
        if op >= 7 {
            mutate_channel(&mut f.svm, &f.channel, |ch| {
                ch.set_settled(400);
                ch.status = 1;
            });
        }
        let ix = if op == 1 {
            f.open_ix()
        } else {
            f.operation(op)
        };
        let before = f.snapshot();
        assert!(f.send(ix).is_err(), "hooked operation {op} accepted V1");
        assert_eq!(f.snapshot(), before, "hooked operation {op}");
    }
}

#[test]
fn sbf_funding_callbacks_and_signer_attenuation() {
    let mut f = Fixture::new(&[0, 1]);
    f.open();
    f.assert_pair(1, 1);
    assert_eq!(u64_at(&f.records()[1], 332), 1_000);
    f.send(f.operation(3)).unwrap();
    f.assert_pair(3, 2);
    assert_eq!(token_balance(&f.svm, &f.escrow), 1_200);
    assert_eq!(
        read_hooked_channel(&f.svm, &f.channel, |c| c.hooks.in_progress),
        0
    );
}

#[test]
fn sbf_open_sealed_distribution_and_prior_withdrawal_callbacks() {
    for withdraw in [false, true] {
        let mut f = Fixture::new(&[2, 3]);
        f.open();
        f.accounting(400, false);
        f.send(f.operation(7)).unwrap();
        f.assert_pair(7, 2);
        assert_eq!(u64_at(f.records().last().unwrap(), 324), 0); // zero refund
        assert_eq!(u64_at(f.records().last().unwrap(), 340), 400); // merchant transfer
        f.accounting(600, true);
        if withdraw {
            f.send(f.operation(8)).unwrap();
            f.assert_pair(8, 3);
            assert_eq!(u64_at(f.records().last().unwrap(), 348), 400);
        }
        f.send(f.operation(7)).unwrap();
        f.assert_pair(7, if withdraw { 4 } else { 3 });
        assert_eq!(u64_at(f.records().last().unwrap(), 340), 200);
        assert_eq!(
            u64_at(f.records().last().unwrap(), 348),
            if withdraw { 0 } else { 400 }
        );
        assert_eq!(token_balance(&f.svm, &f.payee_ata), 600);
        assert_eq!(token_balance(&f.svm, &f.payer_ata), 9_400);
        assert!(f.svm.get_account(&f.escrow).is_none_or(|a| a.lamports == 0));
    }
}

#[test]
fn sbf_each_pre_and_post_failure_rolls_back_every_operation() {
    for op in [1, 3, 7, 8] {
        for sealed in [false, true] {
            if sealed && op != 7 {
                continue;
            }
            for phase in if op <= 3 { [0, 1] } else { [2, 3] } {
                let mut f = Fixture::new(if op <= 3 { &[0, 1] } else { &[2, 3] });
                if op != 1 {
                    f.open();
                }
                if op >= 7 {
                    f.accounting(400, sealed || op == 8);
                }
                f.fail(phase);
                let before = f.snapshot();
                let ix = if op == 1 {
                    f.open_ix()
                } else {
                    f.operation(op)
                };
                let error = f.send(ix).unwrap_err();
                assert_eq!(
                    error.err,
                    TransactionError::InstructionError(
                        0,
                        InstructionError::Custom(700 + phase as u32)
                    )
                );
                assert_eq!(
                    f.snapshot(),
                    before,
                    "op {op} phase {phase} sealed {sealed}"
                );
            }
        }
    }
}

#[test]
fn sbf_zero_refund_withdrawal_is_mandatory_and_cannot_repeat() {
    let mut f = Fixture::new(&[2, 3]);
    f.open();
    f.accounting(1_000, true);
    f.fail(3);
    let before = f.snapshot();
    assert!(f.send(f.operation(8)).is_err());
    assert_eq!(f.snapshot(), before);
    let mut a = f.svm.get_account(&f.recorder).unwrap();
    a.data[0] = 0;
    f.svm.set_account(f.recorder, a).unwrap();
    f.send(f.operation(8)).unwrap();
    f.assert_pair(8, 2);
    assert_eq!(u64_at(f.records().last().unwrap(), 348), 0);
    let before = f.snapshot();
    assert!(f.send(f.operation(8)).is_err());
    assert_eq!(f.snapshot(), before);
    f.send(f.operation(7)).unwrap();
    f.assert_pair(7, 3);
}

#[test]
fn sbf_missing_substituted_and_wrong_phase_accounts_fail_before_callbacks() {
    for case in 0..4 {
        let mut f = Fixture::new(&[0, 1]);
        f.open();
        let mut ix = f.operation(3);
        match case {
            0 => {
                ix.accounts.pop();
            }
            1 => {
                ix.accounts[8].pubkey = f.payee;
            }
            2 => {
                ix.accounts[7] = ix.accounts[11].clone();
            }
            3 => {
                ix.accounts[6].pubkey = SPL_TOKEN;
            }
            _ => unreachable!(),
        }
        let before = f.snapshot();
        assert!(f.send(ix).is_err());
        assert_eq!(f.snapshot(), before);
    }
}

#[test]
fn sbf_strict_refund_ata_failure_never_redirects_principal() {
    let mut f = Fixture::new(&[2, 3]);
    f.open();
    f.accounting(400, true);
    let mut account = f.svm.get_account(&f.payer_ata).unwrap();
    account.data[108] = 2; // frozen SPL token account
    f.svm.set_account(f.payer_ata, account).unwrap();
    let before = f.snapshot();
    assert!(f.send(f.operation(7)).is_err());
    assert_eq!(f.snapshot(), before);
}

#[test]
fn sbf_final_zero_refund_after_withdrawal_still_requires_both_hooks() {
    for phase in [2, 3] {
        let mut f = Fixture::new(&[2, 3]);
        f.open();
        f.accounting(400, true);
        f.send(f.operation(8)).unwrap();
        f.fail(phase);
        let before = f.snapshot();
        let error = f.send(f.operation(7)).unwrap_err();
        assert_eq!(
            error.err,
            TransactionError::InstructionError(0, InstructionError::Custom(700 + phase as u32))
        );
        assert_eq!(f.snapshot(), before);
    }
}

#[test]
// Pinocchio's NotEnoughAccountKeys maps to this deprecated runtime variant.
#[allow(deprecated)]
fn sbf_no_operation_can_omit_mandatory_hooks() {
    for op in [1, 3, 7, 8] {
        let mut f = Fixture::new(if op <= 3 { &[0, 1] } else { &[2, 3] });
        if op != 1 {
            f.open();
        }
        if op >= 7 {
            f.accounting(400, true);
        }
        let mut ix = if op == 1 {
            f.open_ix()
        } else {
            f.operation(op)
        };
        ix.accounts.truncate(match op {
            1 => 14,
            7 => 12,
            _ => 6,
        });
        let before = f.snapshot();
        let error = f.send(ix).unwrap_err();
        assert_eq!(
            error.err,
            TransactionError::InstructionError(0, InstructionError::NotEnoughAccountKeys)
        );
        assert_eq!(f.snapshot(), before);
    }
}

#[test]
fn sbf_indirect_reentry_is_rejected_and_rolls_back_open() {
    let mut f = Fixture::with_mode(&[0, 1], 1);
    let before = f.snapshot();
    let ix = f.open_ix();
    let error = f.send(ix).unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::ReentrancyNotAllowed)
    );
    assert_eq!(f.snapshot(), before);
}

#[test]
fn sbf_guard_rejects_every_entrypoint_before_dispatch() {
    let mut f = Fixture::new(&[]);
    f.open();
    mutate_hooked_channel(&mut f.svm, &f.channel, |c| c.hooks.in_progress = 1);
    for discriminator in (1..=13).chain([payment_channels::event_engine::EMIT_EVENT_IX_DISC]) {
        let before = f.snapshot();
        let error = f
            .send(Instruction {
                program_id: PROGRAM_ID,
                accounts: vec![rw(f.channel)],
                data: vec![discriminator],
            })
            .unwrap_err();
        assert_eq!(
            error.err,
            TransactionError::InstructionError(0, InstructionError::InvalidAccountData)
        );
        assert_eq!(f.snapshot(), before);
    }
}

#[test]
fn sbf_nested_token_cpi_executes_at_depth_three() {
    let mut f = Fixture::with_mode(&[0, 1], 2);
    let ix = f.open_ix();
    let meta = f.send(ix).unwrap();
    assert!(
        meta.logs
            .iter()
            .any(|l| l == &format!("Program {SPL_TOKEN} invoke [3]"))
    );
    assert_eq!(f.records().len(), 2);
    f.send(f.operation(3)).unwrap();
    f.assert_pair(3, 2);
}

#[test]
fn maximum_descriptor_configuration_exceeds_legacy_packet_budget() {
    let f = Fixture::with_mode(&[0, 1, 2, 3], 2);
    let mut ix = f.open_ix();
    // Four enabled slots, four accounts each, maximum static context.
    let mut config = vec![];
    for phase in 0..4 {
        let start = phase * 175;
        let slot = &f.config[start..start + 175];
        config.extend_from_slice(&slot[..42]);
        config.push(32);
        config.extend_from_slice(&[42; 32]);
        config.extend_from_slice(&slot[43..]);
    }
    assert_eq!(config.len(), 828);
    ix.data.truncate(67);
    ix.data.extend(config);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&f.payer.pubkey()),
        &[&f.payer],
        f.svm.latest_blockhash(),
    );
    let packet = 1 + 64 * tx.signatures.len() + tx.message.serialize().len();
    eprintln!("maximum four-descriptor legacy transaction: {packet} bytes (limit 1232)");
    assert!(packet > 1232);
}
