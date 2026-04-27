//! End-to-end validation of `distribute` against the compiled .so.
//!
//! Byte-level mutation stands in for fields whose owning instructions are
//! still stubbed: `status` (`request_close` / `finalize`),
//! `payer_withdrawn_at` (`withdraw_payer`), and `paid_out` (post-prior-
//! distribute simulation). Once those stubs land, the helpers in
//! `tests/common/channel_state.rs` get deleted and each call site becomes
//! a one-line ix submission.

#![allow(clippy::result_large_err)]

use std::str::FromStr;

use litesvm::LiteSVM;
use litesvm_token::CreateAssociatedTokenAccount;
use payment_channels::PaymentChannelsError;
use payment_channels_client::instructions::{Distribute, DistributeInstructionArgs};
use payment_channels_client::types::{DistributeArgs, DistributionEntry, DistributionRecipients};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

mod common;
use common::channel_state;
use common::open::{
    SPL_TOKEN, Split, TOKEN_2022, open_channel, setup_funded_svm_with_token_program,
};
use common::settle::settle_to;
use common::token_2022::{
    EXT_CPI_GUARD, EXT_GROUP_MEMBER_POINTER, EXT_GROUP_POINTER, EXT_IMMUTABLE_OWNER,
    EXT_MEMO_TRANSFER, EXT_METADATA_POINTER, EXT_MINT_CLOSE_AUTHORITY, EXT_TOKEN_GROUP,
    EXT_TOKEN_GROUP_MEMBER, EXT_TOKEN_METADATA, EXT_TRANSFER_FEE_CONFIG, EXT_TRANSFER_HOOK,
    POINTER_EXTENSION_LEN, TOKEN_GROUP_LEN, TOKEN_GROUP_MEMBER_LEN, TOKEN_METADATA_MIN_LEN,
    add_account_extension, add_mint_extension,
};
use common::{expect_custom_err, load_program};

const MAX_DISTRIBUTION_RECIPIENTS: usize = 32;
const STATUS_OPEN: u8 = 0;
const STATUS_FINALIZED: u8 = 1;
const STATUS_CLOSING: u8 = 2;
const GRACE_PERIOD: u32 = 3600;
const DEFAULT_SALT: u64 = 0x1234_5678_9abc_def0;

/// Match `constants::TREASURY_OWNER` — alternating `0xBE 0xEF` × 16.
fn treasury_owner() -> Pubkey {
    let mut b = [0u8; 32];
    for i in 0..16 {
        b[i * 2] = 0xBE;
        b[i * 2 + 1] = 0xEF;
    }
    Pubkey::new_from_array(b)
}

fn token_2022_program_id() -> Pubkey {
    TOKEN_2022
}

fn spl_token_program_id() -> Pubkey {
    SPL_TOKEN
}

fn compute_budget_ix(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(0x02);
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap(),
        accounts: Vec::new(),
        data,
    }
}

/// Build a `DistributionRecipients` from `splits`. Trailing entries are zeroed.
/// `count` is set to `splits.len()`; negative tests mutate it post-hoc to drive
/// the count guard in `validate()`.
fn build_recipients(splits: &[Split]) -> DistributionRecipients {
    let mut entries: [DistributionEntry; MAX_DISTRIBUTION_RECIPIENTS] =
        std::array::from_fn(|_| DistributionEntry {
            recipient: Address::from([0u8; 32]),
            bps: 0,
        });
    for (i, s) in splits.iter().enumerate() {
        entries[i] = DistributionEntry {
            recipient: Address::from(s.owner.to_bytes()),
            bps: s.bps,
        };
    }
    DistributionRecipients {
        count: splits.len() as u8,
        entries,
    }
}

/// Read the `amount` field (bytes 64..72) of a classic SPL Token account.
fn token_balance(svm: &LiteSVM, token_account: &Pubkey) -> u64 {
    let acct = svm
        .get_account(token_account)
        .expect("token account exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[64..72]);
    u64::from_le_bytes(buf)
}

/// Set the `amount` field on a token account directly. Stand-in for the
/// stubbed `withdraw_payer` when a test needs the channel ATA to start at
/// less than the original `deposit`.
fn set_token_balance(svm: &mut LiteSVM, token_account: &Pubkey, amount: u64) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    acct.data[64..72].copy_from_slice(&amount.to_le_bytes());
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

/// Read `paid_out` from the channel account (bytes 28..36).
fn read_paid_out(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    let acct = svm.get_account(channel).expect("channel exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[28..36]);
    u64::from_le_bytes(buf)
}

/// Full distribute ix build with the 8-slot fixed head + dynamic recipient tail.
#[allow(clippy::too_many_arguments)]
fn build_distribute_ix(
    channel: &Pubkey,
    payer: &Pubkey,
    channel_ata: &Pubkey,
    payer_ata: &Pubkey,
    payee_ata: &Pubkey,
    treasury_ata: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    recipient_atas: &[Pubkey],
    recipients: DistributionRecipients,
) -> Instruction {
    let args = DistributeArgs { recipients };
    let remaining: Vec<AccountMeta> = recipient_atas
        .iter()
        .map(|a| AccountMeta::new(*a, false))
        .collect();
    let base = Distribute {
        channel: *channel,
        payer: *payer,
        channel_token_account: *channel_ata,
        payer_token_account: *payer_ata,
        payee_token_account: *payee_ata,
        treasury_token_account: *treasury_ata,
        mint: *mint,
        token_program: *token_program,
    };
    base.instruction_with_remaining_accounts(
        DistributeInstructionArgs {
            distribute_args: args,
        },
        &remaining,
    )
}

/// One-stop scenario fixture. `status`, `paid_out`, and `payer_withdrawn_at`
/// are mutated through the stub stand-in helpers in `common::channel_state`
/// (`request_close` / `finalize` / `withdraw_payer` are not yet implemented).
struct Scenario {
    svm: LiteSVM,
    fee_payer: Keypair,
    mint: Pubkey,
    payer: Pubkey,
    channel: Pubkey,
    channel_ata: Pubkey,
    payer_ata: Pubkey,
    payee_ata: Pubkey,
    treasury_ata: Pubkey,
    token_program: Pubkey,
    recipient_atas: Vec<Pubkey>,
    splits: Vec<Split>,
}

impl Scenario {
    /// Token-2022 default.
    fn build(splits: Vec<Split>, deposit: u64, settled: u64, paid_out: u64, status: u8) -> Self {
        Self::build_with_token_program(
            splits,
            deposit,
            settled,
            paid_out,
            status,
            token_2022_program_id(),
        )
    }

    fn build_with_token_program(
        splits: Vec<Split>,
        deposit: u64,
        settled: u64,
        paid_out: u64,
        status: u8,
        token_program: Pubkey,
    ) -> Self {
        let mut svm = load_program();
        let fee_payer = Keypair::new();
        svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&treasury_owner(), 1_000_000_000).unwrap();

        let (payer_kp, mint, payer_ata) =
            setup_funded_svm_with_token_program(&mut svm, deposit, &token_program);
        let payer = payer_kp.pubkey();

        let opened = open_channel(
            &mut svm,
            &payer_kp,
            &mint,
            &payer_ata,
            DEFAULT_SALT,
            deposit,
            GRACE_PERIOD,
            &splits,
            &token_program,
        );
        let channel = opened.channel;
        let channel_ata = opened.channel_ata;

        // Payee ATA must be created here, after `open_channel` mints the
        // payee Pubkey internally — `distribute` is permissionless and only
        // *validates* this account, so any prior caller (typically the payee)
        // is responsible for creating it.
        svm.airdrop(&opened.payee, 1_000_000).ok();
        let payee_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&opened.payee)
            .token_program_id(&token_program)
            .send()
            .expect("payee ATA");

        if settled > 0 {
            settle_to(
                &mut svm,
                &fee_payer,
                &channel,
                &opened.authorized_signer,
                settled,
                0,
            );
        }

        if paid_out > 0 {
            channel_state::set_paid_out(&mut svm, &channel, paid_out);
        }

        if status != STATUS_OPEN {
            channel_state::set_status(&mut svm, &channel, status);
        }

        let treasury_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&treasury_owner())
            .token_program_id(&token_program)
            .send()
            .expect("treasury ATA");

        let mut recipient_atas = Vec::with_capacity(splits.len());
        let mut created_recipient_atas = Vec::<(Pubkey, Pubkey)>::new();
        for s in &splits {
            if let Some((_, ata)) = created_recipient_atas
                .iter()
                .find(|(owner, _)| owner == &s.owner)
            {
                recipient_atas.push(*ata);
                continue;
            }
            svm.airdrop(&s.owner, 1_000_000).ok();
            let r_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
                .owner(&s.owner)
                .token_program_id(&token_program)
                .send()
                .expect("recipient ATA");
            created_recipient_atas.push((s.owner, r_ata));
            recipient_atas.push(r_ata);
        }

        Self {
            svm,
            fee_payer,
            mint,
            payer,
            channel,
            channel_ata,
            payer_ata,
            payee_ata,
            treasury_ata,
            token_program,
            recipient_atas,
            splits,
        }
    }

    /// Typed recipients matching the scenario's declared splits.
    fn recipients(&self) -> DistributionRecipients {
        build_recipients(&self.splits)
    }

    fn distribute_ix(&self) -> Instruction {
        build_distribute_ix(
            &self.channel,
            &self.payer,
            &self.channel_ata,
            &self.payer_ata,
            &self.payee_ata,
            &self.treasury_ata,
            &self.mint,
            &self.token_program,
            &self.recipient_atas,
            self.recipients(),
        )
    }

    fn send(&mut self, ix: Instruction) -> litesvm::types::TransactionResult {
        let blockhash = self.svm.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[compute_budget_ix(1_400_000), ix],
            Some(&self.fee_payer.pubkey()),
            &[&self.fee_payer],
            blockhash,
        );
        self.svm.send_transaction(tx)
    }
}

/// Re-order the `(deposit, settled, paid_out)` tuple at the call site so the
/// test literal reads in deposit→settled→paid_out order regardless of the
/// positional args to `Scenario::build`.
#[inline]
fn pool(deposit: u64, paid_out: u64, settled: u64) -> (u64, u64, u64) {
    (deposit, settled, paid_out)
}

// ---------------------------------------------------------------------------
// Tests

#[test]
fn happy_path_open_splits() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 3000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 1000,
        },
    ];
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build(splits.clone(), deposit, settled, paid_out, STATUS_OPEN);

    let pool_amount = settled - paid_out;
    s.send(s.distribute_ix()).expect("distribute ok");

    // 40 / 30 / 10 % to recipients; remaining 20 % is the payee implicit
    // remainder. OPEN distribute does NOT refund the payer.
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 30_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[2]), 10_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 20_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), paid_out + pool_amount);
}

#[test]
fn happy_path_open_splits_spl_token() {
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 2500,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 2500,
        },
    ];
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        paid_out,
        STATUS_OPEN,
        spl_token_program_id(),
    );

    s.send(s.distribute_ix()).expect("spl distribute ok");

    // 25 / 25 % to recipients; payee picks up the 50 % implicit remainder.
    // OPEN distribute does NOT refund the payer.
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 25_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}

#[test]
fn happy_path_finalized_tombstone() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    // Finalized, deposit=200k, settled=150k, paid_out=0.
    // Pool=150k splits: 50 % recipient (75k), 50 % payee implicit remainder
    // (75k). Payer ATA receives only the FINALIZED refund, deposit−settled = 50k.
    let (deposit, settled, paid_out) = pool(200_000, 0, 150_000);
    let mut s = Scenario::build(splits.clone(), deposit, settled, paid_out, STATUS_FINALIZED);

    let payer_balance_before = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_before = s.svm.get_account(&s.channel).unwrap().lamports;
    let channel_ata_lamports_before = s.svm.get_account(&s.channel_ata).unwrap().lamports;

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);

    // Tombstone: channel PDA rent + channel_token_account rent flow to payer.
    let payer_after = s.svm.get_account(&s.payer).unwrap().lamports;
    let channel_lamports_after = s
        .svm
        .get_account(&s.channel)
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(channel_lamports_after, 0);
    assert_eq!(
        payer_after - payer_balance_before,
        channel_lamports_before + channel_ata_lamports_before
    );
}

#[test]
fn happy_path_finalized_tombstone_spl_token() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let (deposit, settled, paid_out) = pool(200_000, 0, 150_000);
    let mut s = Scenario::build_with_token_program(
        splits,
        deposit,
        settled,
        paid_out,
        STATUS_FINALIZED,
        spl_token_program_id(),
    );

    s.send(s.distribute_ix()).expect("spl finalized ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 50_000);
    assert_eq!(
        s.svm
            .get_account(&s.channel)
            .map(|a| a.lamports)
            .unwrap_or(0),
        0
    );
}

#[test]
fn finalized_zero_pool_still_refunds_and_tombstones() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let (deposit, settled, paid_out) = pool(200_000, 100_000, 100_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_FINALIZED);

    // Simulate a prior OPEN distribution that already paid the entire settled
    // pool; only the payer refund (deposit − settled) remains in escrow.
    set_token_balance(&mut s.svm, &s.channel_ata, deposit - settled);

    s.send(s.distribute_ix()).expect("finalized zero pool ok");

    // pool == 0 → no recipient or payee transfer; only the FINALIZED payer
    // refund branch fires.
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), deposit - settled);
    assert_eq!(
        s.svm
            .get_account(&s.channel)
            .map(|a| a.lamports)
            .unwrap_or(0),
        0
    );
}

#[test]
fn happy_path_finalized_already_withdrawn() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let (deposit, settled, paid_out) = pool(200_000, 0, 150_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_FINALIZED);

    // `withdraw_payer` is stubbed, so simulate it: payer pulled
    // (deposit − settled) out of escrow earlier and `payer_withdrawn_at` is
    // set, so distribute must skip the refund branch.
    channel_state::set_payer_withdrawn_at(&mut s.svm, &s.channel, 1_700_000_000);
    set_token_balance(&mut s.svm, &s.channel_ata, settled - paid_out);

    s.send(s.distribute_ix()).expect("distribute ok");

    // Recipient gets 50 % of the 150k pool; payee picks up the 50 % implicit
    // remainder. Payer-refund branch did NOT run, so the payer ATA stays at 0.
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 75_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
}

#[test]
fn bad_preimage_hash() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    // Tamper the on-chain distribution_hash so the rehash diverges.
    let mut acct = s.svm.get_account(&s.channel).unwrap();
    acct.data[56] ^= 0xFF;
    s.svm
        .set_account(s.channel, acct)
        .expect("overwrite channel");
    let res = s.send(s.distribute_ix());
    expect_custom_err(res, PaymentChannelsError::InvalidDistributionHash);
}

#[test]
fn token_2022_allowed_mint_and_immutable_owner_account_extensions_succeed() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 5000,
    }];
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);
    for (extension_type, value_len) in [
        (EXT_METADATA_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_METADATA, TOKEN_METADATA_MIN_LEN),
        (EXT_GROUP_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP, TOKEN_GROUP_LEN),
        (EXT_GROUP_MEMBER_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP_MEMBER, TOKEN_GROUP_MEMBER_LEN),
    ] {
        add_mint_extension(&mut s.svm, &s.mint, extension_type, value_len);
    }
    add_account_extension(&mut s.svm, &s.recipient_atas[0], EXT_IMMUTABLE_OWNER, 0);

    s.send(s.distribute_ix()).expect("allowed extensions ok");

    // 50 % recipient, 50 % payee; payer untouched on OPEN.
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 50_000);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}

#[test]
fn unsupported_token_2022_mint_extensions_reject_without_state_changes() {
    for (extension_type, value_len) in [
        (EXT_TRANSFER_FEE_CONFIG, 108),
        (EXT_TRANSFER_HOOK, 64),
        (EXT_MINT_CLOSE_AUTHORITY, 32),
    ] {
        let splits = vec![Split {
            owner: Pubkey::new_unique(),
            bps: 5000,
        }];
        let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_OPEN);
        let paid_out_before = read_paid_out(&s.svm, &s.channel);
        add_mint_extension(&mut s.svm, &s.mint, extension_type, value_len);

        let res = s.send(s.distribute_ix());

        expect_custom_err(res, PaymentChannelsError::UnsupportedTokenExtensions);
        assert_eq!(read_paid_out(&s.svm, &s.channel), paid_out_before);
        assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
        assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    }
}

#[test]
fn unsupported_token_2022_account_extensions_reject_without_state_changes() {
    for extension_type in [EXT_MEMO_TRANSFER, EXT_CPI_GUARD] {
        let splits = vec![Split {
            owner: Pubkey::new_unique(),
            bps: 5000,
        }];
        let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_OPEN);
        let paid_out_before = read_paid_out(&s.svm, &s.channel);
        add_account_extension(&mut s.svm, &s.recipient_atas[0], extension_type, 1);

        let res = s.send(s.distribute_ix());

        expect_custom_err(res, PaymentChannelsError::UnsupportedTokenExtensions);
        assert_eq!(read_paid_out(&s.svm, &s.channel), paid_out_before);
        assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 0);
        assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    }
}

#[test]
fn num_recipients_zero_pays_full_pool_to_payee() {
    // count == 0 is the vanilla two-party shape: pool drains entirely to the
    // payee, no recipient ATAs in the tail. Open the channel with `splits = []`
    // so the on-chain hash matches the zero-recipient preimage.
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build(vec![], deposit, settled, paid_out, STATUS_OPEN);

    let pool_amount = settled - paid_out;
    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.payee_ata), pool_amount);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), pool_amount);
}

#[test]
fn wrong_recipient_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_OPEN);
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .token_program_id(&s.token_program)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &[rogue_ata],
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidRecipientAccount);
}

#[test]
fn wrong_treasury_ata() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_OPEN);
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .token_program_id(&s.token_program)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &rogue_ata,
        &s.mint,
        &s.token_program,
        &s.recipient_atas,
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::TreasuryAddressMismatch);
}

#[test]
fn wrong_token_program() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_OPEN);
    let system_id = Pubkey::default();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &s.treasury_ata,
        &s.mint,
        &system_id,
        &s.recipient_atas,
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidTokenProgram);
}

#[test]
fn pool_zero_rejects() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    // Right after open: settled = 0, paid_out = 0 → pool = 0.
    let mut s = Scenario::build(splits, 200_000, 0, 0, STATUS_OPEN);
    expect_custom_err(
        s.send(s.distribute_ix()),
        PaymentChannelsError::NothingToDistribute,
    );
}

#[test]
fn status_closing_rejects() {
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_CLOSING);
    expect_custom_err(
        s.send(s.distribute_ix()),
        PaymentChannelsError::ChannelNotDistributable,
    );
}

#[test]
fn num_recipients_exceeds_max() {
    // 33 > MAX_DISTRIBUTION_RECIPIENTS = 32 → validate() trips the count guard
    // without needing 33 ATAs or a hash match.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_OPEN);
    let mut bad = s.recipients();
    bad.count = 33;
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &s.payee_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &s.recipient_atas,
        bad,
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidRecipientCount);
}

#[test]
fn bps_sum_equals_10000_no_payee_share() {
    // Σ shareBps == 10_000 — payee carve-out is zero, recipients fully drain
    // the pool. Payee ATA is still validated but receives nothing.
    let splits = vec![
        Split {
            owner: Pubkey::new_unique(),
            bps: 6000,
        },
        Split {
            owner: Pubkey::new_unique(),
            bps: 4000,
        },
    ];
    let (deposit, settled, paid_out) = pool(200_000, 0, 100_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 60_000);
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[1]), 40_000);
    assert_eq!(token_balance(&s.svm, &s.payee_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.payer_ata), 0);
    assert_eq!(token_balance(&s.svm, &s.treasury_ata), 0);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}

#[test]
fn wrong_payee_ata() {
    // ATA owned by an unrelated wallet — `derive_ata(&ch.payee, ...)` mismatch
    // must fire before any transfer.
    let splits = vec![Split {
        owner: Pubkey::new_unique(),
        bps: 1000,
    }];
    let mut s = Scenario::build(splits, 200_000, 0, 100_000, STATUS_OPEN);
    let rogue_owner = Pubkey::new_unique();
    s.svm.airdrop(&rogue_owner, 1_000_000).ok();
    let rogue_ata = CreateAssociatedTokenAccount::new(&mut s.svm, &s.fee_payer, &s.mint)
        .token_program_id(&s.token_program)
        .owner(&rogue_owner)
        .send()
        .unwrap();
    let ix = build_distribute_ix(
        &s.channel,
        &s.payer,
        &s.channel_ata,
        &s.payer_ata,
        &rogue_ata,
        &s.treasury_ata,
        &s.mint,
        &s.token_program,
        &s.recipient_atas,
        s.recipients(),
    );
    expect_custom_err(s.send(ix), PaymentChannelsError::InvalidPayeeTokenAccount);
}

#[test]
fn max_recipients_accepted() {
    let recipient = Pubkey::new_unique();
    let splits: Vec<Split> = (0..MAX_DISTRIBUTION_RECIPIENTS)
        .map(|_| Split {
            owner: recipient,
            bps: 1,
        })
        .collect();
    let (deposit, settled, paid_out) = pool(2_000_000, 0, 1_000_000);
    let mut s = Scenario::build(splits, deposit, settled, paid_out, STATUS_OPEN);

    s.send(s.distribute_ix()).expect("distribute ok");

    assert_eq!(s.recipient_atas.len(), MAX_DISTRIBUTION_RECIPIENTS);
    assert!(
        s.recipient_atas
            .iter()
            .all(|ata| ata == &s.recipient_atas[0])
    );
    assert_eq!(token_balance(&s.svm, &s.recipient_atas[0]), 3_200);
    assert_eq!(read_paid_out(&s.svm, &s.channel), settled);
}
