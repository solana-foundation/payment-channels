//! End-to-end LiteSVM scenarios for the two-phase terminal close.
//!
//! Phase 1 is the SEALED `distribute`: it is UNGATED, so every token leg
//! (recipient splits, implicit payee share, payer refund, treasury sweep)
//! pays out immediately and the escrow ATA closes — nobody's money ever
//! waits on a slot. If the reclaim gate has already passed, the same
//! instruction deallocates the channel PDA too (fast path, pinned by
//! `distribute::e2e::happy_path_sealed_close`); otherwise the channel is
//! left `Distributed`, holding only its own rent, so the address stays
//! occupied until its `open_slot` has aged out of the open window. Because
//! `open_slot` is a channel PDA seed, that gate is what guarantees the same
//! address can never exist twice: once the address is finally surrendered,
//! its `open_slot` no longer clears the open window, so no `open` can ever
//! re-derive it — every incarnation gets a fresh address, and a voucher
//! (which binds an address via `channel_id`) can never meet a second
//! incarnation it would be valid for.
//!
//! Phase 2 is `reclaim`: a permissionless, slot-gated crank that drains the
//! `Distributed` PDA's lamports to the recorded rent payer and frees the address.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels::constants::OPEN_SLOT_WINDOW;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::{
    Distribute, DistributeInstructionArgs, Open, OpenInstructionArgs, RequestClose, Seal, Settle,
    SettleAndSeal, SettleAndSealInstructionArgs, TopUp, TopUpInstructionArgs, WithdrawPayer,
};
use payment_channels_client::types::{
    DistributeArgs, DistributionEntry, OpenArgs, SettleAndSealArgs, TopUpArgs,
};
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{
    ATA_PROGRAM, INSTRUCTIONS_SYSVAR, PROGRAM_ID, ProgramLoader, SPL_TOKEN, SYSTEM_PROGRAM,
    SYSVAR_RENT, build_reclaim_ix, channel_open_slot, current_slot, event_authority,
    expect_custom_err, expect_instruction_err, read_channel, token_balance, treasury_owner,
    voucher::{build_ed25519_ix, voucher, voucher_payload},
    warp_past_close_gate,
};

const GRACE_PERIOD: u32 = 3_600;
const DEFAULT_SALT: u64 = 0x1234_5678_9abc_def0;
const DEPOSIT: u64 = 200_000;
const SETTLED: u64 = 150_000;
/// Single explicit recipient at 50%; the payee keeps the implicit half.
const RECIPIENT_BPS: u16 = 5_000;

/// Assert the reclaimed shape of an account: every lamport gone and the
/// account reaped by the runtime — `get_account` returns `None`, or an
/// empty 0-lamport system-owned shell if the runtime kept the entry around.
fn assert_reclaimed(svm: &LiteSVM, address: &Pubkey) {
    match svm.get_account(address) {
        None => {}
        Some(acct) => {
            assert_eq!(acct.lamports, 0, "reclaimed account keeps no lamports");
            assert!(acct.data.is_empty(), "reclaimed account keeps no data");
            assert_eq!(
                acct.owner, SYSTEM_PROGRAM,
                "reclaimed account reverts to the system program"
            );
        }
    }
}

fn lamports(svm: &LiteSVM, address: &Pubkey) -> u64 {
    svm.get_account(address).map_or(0, |a| a.lamports)
}

/// Send `ixs` as one tx signed by `fee_payer` (+ `extra_signers`). Bumps the
/// blockhash first so repeated identical instruction lists don't collide on
/// tx signature.
fn send_tx(
    svm: &mut LiteSVM,
    fee_payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
) -> litesvm::types::TransactionResult {
    svm.expire_blockhash();
    let mut signers: Vec<&Keypair> = vec![fee_payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&fee_payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
}

/// One channel's addresses within an [`Env`]. Channels share every base
/// account and differ only by salt and `open_slot` (both PDA seeds), so
/// several can coexist in one SVM.
struct Chan {
    salt: u64,
    /// Slot committed at `open` — a PDA seed, so it is fixed at derivation
    /// time and makes the address per-incarnation by construction.
    open_slot: u64,
    channel: Pubkey,
    channel_ata: Pubkey,
}

/// Shared fixture: funded payer (also the channel rent payer), payee
/// keypair (must sign `settle_and_seal`), authorized signer, mint, and
/// every ATA a `distribute` call validates.
struct Env {
    svm: LiteSVM,
    fee_payer: Keypair,
    payer: Keypair,
    payee: Keypair,
    authorized_signer: Keypair,
    mint: Pubkey,
    payer_ata: Pubkey,
    payee_ata: Pubkey,
    treasury_ata: Pubkey,
    recipient_owner: Pubkey,
    recipient_ata: Pubkey,
}

impl Env {
    /// Build the shared accounts and fund the payer ATA with `mint_amount`
    /// tokens (enough for every `open` the test intends to run).
    fn new(mint_amount: u64) -> Self {
        let mut svm = LiteSVM::load_program();
        let fee_payer = Keypair::new();
        svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&treasury_owner(), 1_000_000_000).unwrap();

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
        let mint = CreateMint::new(&mut svm, &payer)
            .decimals(0)
            .token_program_id(&SPL_TOKEN)
            .send()
            .unwrap();
        let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
            .token_program_id(&SPL_TOKEN)
            .send()
            .unwrap();
        MintTo::new(&mut svm, &payer, &mint, &payer_ata, mint_amount)
            .token_program_id(&SPL_TOKEN)
            .send()
            .unwrap();

        let payee = Keypair::new();
        svm.airdrop(&payee.pubkey(), 1_000_000).unwrap();
        let payee_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&payee.pubkey())
            .token_program_id(&SPL_TOKEN)
            .send()
            .expect("payee ATA");

        let treasury_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&treasury_owner())
            .token_program_id(&SPL_TOKEN)
            .send()
            .expect("treasury ATA");

        let recipient_owner = Pubkey::new_unique();
        svm.airdrop(&recipient_owner, 1_000_000).unwrap();
        let recipient_ata = CreateAssociatedTokenAccount::new(&mut svm, &fee_payer, &mint)
            .owner(&recipient_owner)
            .token_program_id(&SPL_TOKEN)
            .send()
            .expect("recipient ATA");

        Self {
            svm,
            fee_payer,
            payer,
            payee,
            authorized_signer: Keypair::new(),
            mint,
            payer_ata,
            payee_ata,
            treasury_ata,
            recipient_owner,
            recipient_ata,
        }
    }

    /// Derive the addresses of the incarnation that would be opened *right
    /// now*: `open_slot` (the current slot) is a PDA seed, so it must be
    /// fixed before derivation, and the same `Chan` opened at a later slot
    /// would be a different address.
    fn chan(&self, salt: u64) -> Chan {
        let open_slot = current_slot(&self.svm);
        let (channel, _) = Pubkey::find_program_address(
            &[
                b"channel",
                self.payer.pubkey().as_ref(),
                self.payee.pubkey().as_ref(),
                self.mint.as_ref(),
                self.authorized_signer.pubkey().as_ref(),
                &salt.to_le_bytes(),
                &open_slot.to_le_bytes(),
            ],
            &PROGRAM_ID,
        );
        let (channel_ata, _) = Pubkey::find_program_address(
            &[channel.as_ref(), SPL_TOKEN.as_ref(), self.mint.as_ref()],
            &ATA_PROGRAM,
        );
        Chan {
            salt,
            open_slot,
            channel,
            channel_ata,
        }
    }

    fn recipients(&self) -> Vec<DistributionEntry> {
        vec![DistributionEntry {
            recipient: self.recipient_owner,
            bps: RECIPIENT_BPS,
        }]
    }

    fn open(&mut self, chan: &Chan, deposit: u64) {
        let ix = Open {
            payer: self.payer.pubkey(),
            rent_payer: self.payer.pubkey(),
            payee: self.payee.pubkey(),
            mint: self.mint,
            authorized_signer: self.authorized_signer.pubkey(),
            channel: chan.channel,
            payer_token_account: self.payer_ata,
            channel_token_account: chan.channel_ata,
            token_program: SPL_TOKEN,
            system_program: SYSTEM_PROGRAM,
            rent: SYSVAR_RENT,
            associated_token_program: ATA_PROGRAM,
            event_authority: event_authority(),
            self_program: PROGRAM_ID,
        }
        .instruction(OpenInstructionArgs {
            open_args: OpenArgs {
                salt: chan.salt,
                deposit,
                grace_period: GRACE_PERIOD,
                // Must match the slot committed at derivation time — it is
                // a PDA seed, so any other value lands at another address.
                open_slot: chan.open_slot,
                recipients: self.recipients(),
            },
        });
        send_tx(&mut self.svm, &self.payer, &[], &[ix]).expect("open ok");
    }

    /// `[ed25519, settle]` where the voucher is signed for
    /// `voucher_channel` but the settle ix targets `target` — lets callers
    /// present a dead incarnation's voucher against a live channel.
    fn settle_pair_cross(
        &self,
        voucher_channel: Pubkey,
        target: Pubkey,
        cumulative_amount: u64,
    ) -> [Instruction; 2] {
        let voucher = voucher(voucher_channel, cumulative_amount, 0);
        let payload = voucher_payload(&voucher);
        let signature: [u8; 64] = self.authorized_signer.sign_message(&payload).into();
        let pubkey = self.authorized_signer.pubkey().to_bytes();
        [
            build_ed25519_ix(&pubkey, &signature, &payload),
            Settle {
                channel: target,
                instructions_sysvar: INSTRUCTIONS_SYSVAR,
            }
            .instruction(),
        ]
    }

    /// `[ed25519, settle]` pair bound to `chan`'s own address.
    fn settle_pair(&self, chan: &Chan, cumulative_amount: u64) -> [Instruction; 2] {
        self.settle_pair_cross(chan.channel, chan.channel, cumulative_amount)
    }

    /// Advance the watermark. The voucher binds the incarnation through its
    /// `channel_id` alone — `open_slot` lives in the PDA seeds now.
    fn settle_to(&mut self, chan: &Chan, cumulative_amount: u64) {
        let ixs = self.settle_pair(chan, cumulative_amount);
        send_tx(&mut self.svm, &self.fee_payer, &[], &ixs).expect("settle ok");
    }

    fn settle_and_seal_ix(&self, chan: &Chan) -> Instruction {
        SettleAndSeal {
            payee: self.payee.pubkey(),
            channel: chan.channel,
            instructions_sysvar: INSTRUCTIONS_SYSVAR,
        }
        .instruction(SettleAndSealInstructionArgs {
            settle_and_seal_args: SettleAndSealArgs { has_voucher: 0 },
        })
    }

    /// Payee-signed cooperative close against the already-settled
    /// watermark (`has_voucher == 0`): OPEN → SEALED.
    fn settle_and_seal(&mut self, chan: &Chan) {
        let ix = self.settle_and_seal_ix(chan);
        send_tx(&mut self.svm, &self.fee_payer, &[&self.payee], &[ix]).expect("settle_and_seal ok");
    }

    fn distribute_ix(&self, chan: &Chan) -> Instruction {
        Distribute {
            channel: chan.channel,
            payer: self.payer.pubkey(),
            rent_payer: self.payer.pubkey(),
            channel_token_account: chan.channel_ata,
            payer_token_account: self.payer_ata,
            payee_token_account: self.payee_ata,
            treasury_token_account: self.treasury_ata,
            mint: self.mint,
            token_program: SPL_TOKEN,
            event_authority: event_authority(),
            self_program: PROGRAM_ID,
        }
        .instruction_with_remaining_accounts(
            DistributeInstructionArgs {
                distribute_args: DistributeArgs {
                    recipients: self.recipients(),
                },
            },
            &[AccountMeta::new(self.recipient_ata, false)],
        )
    }

    /// Drive `chan` to `Distributed` via the two-phase path: open → voucher
    /// settle → cooperative seal → ungated SEALED distribute, all
    /// strictly inside the epoch window so the fast path never triggers.
    fn close_two_phase(&mut self, chan: &Chan) {
        self.open(chan, DEPOSIT);
        self.settle_to(chan, SETTLED);
        self.settle_and_seal(chan);

        let open_slot = channel_open_slot(&self.svm, &chan.channel);
        assert!(
            current_slot(&self.svm) <= open_slot + OPEN_SLOT_WINDOW,
            "fixture must distribute inside the epoch window"
        );
        let ix = self.distribute_ix(chan);
        send_tx(&mut self.svm, &self.fee_payer, &[], &[ix]).expect("ungated sealed distribute ok");
        read_channel(&self.svm, &chan.channel, |ch| {
            assert_eq!(ch.status, ChannelStatus::Distributed as u8);
        });
    }
}

// ===========================================================================
// Two-phase happy path + exact rent accounting.
//
// The fast path (warp first, then distribute → PDA gone in the same tx, no
// reclaim needed) is pinned by `distribute::e2e::happy_path_sealed_close`,
// which asserts full deallocation plus recovery of channel rent + escrow-ATA
// rent in one instruction.

#[test]
fn two_phase_close_pays_immediately_then_reclaim_frees_rent() {
    let mut env = Env::new(DEPOSIT);
    let chan = env.chan(DEFAULT_SALT);
    env.open(&chan, DEPOSIT);
    env.settle_to(&chan, SETTLED);
    env.settle_and_seal(&chan);

    let open_slot = channel_open_slot(&env.svm, &chan.channel);
    assert!(
        current_slot(&env.svm) <= open_slot + OPEN_SLOT_WINDOW,
        "still inside the epoch window: the fast path is unavailable"
    );

    let payer_before = lamports(&env.svm, &env.payer.pubkey());
    let channel_rent = lamports(&env.svm, &chan.channel);
    let escrow_rent = lamports(&env.svm, &chan.channel_ata);

    // Phase 1: distribute inside the window. Token movement is never
    // slot-gated — every leg pays out right now.
    let ix = env.distribute_ix(&chan);
    send_tx(&mut env.svm, &env.fee_payer, &[], &[ix]).expect("ungated distribute ok");

    assert_eq!(token_balance(&env.svm, &env.recipient_ata), 75_000);
    assert_eq!(token_balance(&env.svm, &env.payee_ata), 75_000);
    assert_eq!(token_balance(&env.svm, &env.payer_ata), DEPOSIT - SETTLED);
    assert_eq!(token_balance(&env.svm, &env.treasury_ata), 0);

    // The escrow ATA is closed and its rent lands at the rent payer — the
    // ONLY lamports the payer gains in phase 1.
    assert!(
        env.svm
            .get_account(&chan.channel_ata)
            .is_none_or(|a| a.lamports == 0 && a.data.is_empty()),
        "escrow ATA closed"
    );
    let payer_mid = lamports(&env.svm, &env.payer.pubkey());
    assert_eq!(payer_mid - payer_before, escrow_rent);

    // The channel PDA survives as an inert `Distributed` marker holding exactly
    // its own rent: the address must stay occupied until its `open_slot`
    // ages out of the open window, so the same address (whose seeds include
    // that `open_slot`) can never be re-created.
    assert_eq!(lamports(&env.svm, &chan.channel), channel_rent);
    read_channel(&env.svm, &chan.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Distributed as u8);
    });

    // Phase 2 too early: inside the window reclaim rejects and nothing moves.
    let res = send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan.channel, &env.payer.pubkey())],
    );
    expect_custom_err(res, PaymentChannelsError::ChannelCloseTooEarly);
    assert_eq!(lamports(&env.svm, &chan.channel), channel_rent);
    assert_eq!(lamports(&env.svm, &env.payer.pubkey()), payer_mid);
    read_channel(&env.svm, &chan.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Distributed as u8);
    });

    // Past the gate the permissionless crank frees the address and returns
    // the entire PDA balance to the recorded rent payer.
    warp_past_close_gate(&mut env.svm, &chan.channel);
    send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan.channel, &env.payer.pubkey())],
    )
    .expect("reclaim ok");

    assert_reclaimed(&env.svm, &chan.channel);
    let payer_after = lamports(&env.svm, &env.payer.pubkey());
    assert_eq!(payer_after - payer_mid, channel_rent);
}

// ===========================================================================
// A `Distributed` channel is inert: it occupies the address and nothing else.

#[test]
fn closed_channel_rejects_every_lifecycle_instruction() {
    let mut env = Env::new(DEPOSIT + 1_000); // headroom for the top_up attempt
    let chan = env.chan(DEFAULT_SALT);
    env.close_two_phase(&chan);

    // settle: correctly signed, correct-address, monotonic voucher — only
    // the terminal status disqualifies it.
    let ixs = env.settle_pair(&chan, SETTLED + 500);
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[], &ixs),
        PaymentChannelsError::InvalidChannelStatus,
    );

    // top_up (needs OPEN).
    let ix = TopUp {
        payer: env.payer.pubkey(),
        channel: chan.channel,
        payer_token_account: env.payer_ata,
        channel_token_account: chan.channel_ata,
        mint: env.mint,
        token_program: SPL_TOKEN,
    }
    .instruction(TopUpInstructionArgs {
        top_up_args: TopUpArgs { amount: 1_000 },
    });
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[&env.payer], &[ix]),
        PaymentChannelsError::InvalidChannelStatus,
    );

    // request_close (needs OPEN).
    let ix = RequestClose {
        payer: env.payer.pubkey(),
        channel: chan.channel,
    }
    .instruction();
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[&env.payer], &[ix]),
        PaymentChannelsError::InvalidChannelStatus,
    );

    // settle_and_seal (needs OPEN or CLOSING).
    let ix = env.settle_and_seal_ix(&chan);
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[&env.payee], &[ix]),
        PaymentChannelsError::InvalidChannelStatus,
    );

    // seal (needs CLOSING).
    let ix = Seal {
        channel: chan.channel,
    }
    .instruction();
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[], &[ix]),
        PaymentChannelsError::InvalidChannelStatus,
    );

    // withdraw_payer (needs SEALED).
    let ix = WithdrawPayer {
        payer: env.payer.pubkey(),
        channel: chan.channel,
        channel_token_account: chan.channel_ata,
        payer_token_account: env.payer_ata,
        mint: env.mint,
        token_program: SPL_TOKEN,
    }
    .instruction();
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[&env.payer], &[ix]),
        PaymentChannelsError::InvalidChannelStatus,
    );

    // A second distribute (needs OPEN or SEALED).
    let ix = env.distribute_ix(&chan);
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[], &[ix]),
        PaymentChannelsError::ChannelNotDistributable,
    );

    // The marker is untouched by the whole barrage.
    read_channel(&env.svm, &chan.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Distributed as u8);
    });
}

// ===========================================================================
// reclaim guards under a real SVM.

#[test]
fn reclaim_wrong_rent_payer_rejects() {
    let mut env = Env::new(DEPOSIT);
    let chan = env.chan(DEFAULT_SALT);
    env.close_two_phase(&chan);
    warp_past_close_gate(&mut env.svm, &chan.channel);

    // Past the gate, correct status — only the rent-payer binding fires. A
    // permissionless cranker cannot redirect the freed rent to itself.
    let channel_rent = lamports(&env.svm, &chan.channel);
    let rogue = Pubkey::new_unique();
    let res = send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan.channel, &rogue)],
    );
    expect_custom_err(res, PaymentChannelsError::InvalidChannelRentPayer);
    assert_eq!(lamports(&env.svm, &chan.channel), channel_rent);
    assert_eq!(lamports(&env.svm, &rogue), 0);
}

#[test]
fn reclaim_on_open_channel_rejects() {
    let mut env = Env::new(DEPOSIT);
    let chan = env.chan(DEFAULT_SALT);
    env.open(&chan, DEPOSIT);
    // Even past the gate: the status guard fires, not the slot gate.
    warp_past_close_gate(&mut env.svm, &chan.channel);

    let res = send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan.channel, &env.payer.pubkey())],
    );
    expect_custom_err(res, PaymentChannelsError::InvalidChannelStatus);
    read_channel(&env.svm, &chan.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Open as u8);
    });
}

#[test]
fn reclaim_on_sealed_channel_rejects() {
    // SEALED still owes its token legs (splits, refund, sweep) to
    // `distribute`; the rent may not be freed before they are paid.
    let mut env = Env::new(DEPOSIT);
    let chan = env.chan(DEFAULT_SALT);
    env.open(&chan, DEPOSIT);
    env.settle_to(&chan, SETTLED);
    env.settle_and_seal(&chan);
    warp_past_close_gate(&mut env.svm, &chan.channel);

    let res = send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan.channel, &env.payer.pubkey())],
    );
    expect_custom_err(res, PaymentChannelsError::InvalidChannelStatus);
    read_channel(&env.svm, &chan.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Sealed as u8);
    });
}

#[test]
fn reclaim_gate_boundaries() {
    let mut env = Env::new(DEPOSIT);
    let chan = env.chan(DEFAULT_SALT);
    env.close_two_phase(&chan);
    let open_slot = channel_open_slot(&env.svm, &chan.channel);

    // `clock.slot == open_slot + OPEN_SLOT_WINDOW` still fails: the gate is
    // strict (`>`), the exact complement of the open window's inclusive
    // upper edge (`open_slot >= clock.slot - OPEN_SLOT_WINDOW`). The address
    // stays occupied for every slot at which its own `open_slot` — a PDA
    // seed — would still clear the open window, so the same address can
    // never be re-created.
    env.svm.warp_to_slot(open_slot + OPEN_SLOT_WINDOW);
    let res = send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan.channel, &env.payer.pubkey())],
    );
    expect_custom_err(res, PaymentChannelsError::ChannelCloseTooEarly);
    read_channel(&env.svm, &chan.channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Distributed as u8);
    });

    // One slot past the window the reclaim unlocks.
    env.svm.warp_to_slot(open_slot + OPEN_SLOT_WINDOW + 1);
    send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan.channel, &env.payer.pubkey())],
    )
    .expect("reclaim one slot past the window ok");
    assert_reclaimed(&env.svm, &chan.channel);
}

// ===========================================================================
// Batching: reclaim's two-account, no-signer footprint exists so operators
// can sweep many dead channels in one transaction.

#[test]
fn batched_reclaims_free_two_channels_in_one_transaction() {
    let mut env = Env::new(2 * DEPOSIT);
    let chan_a = env.chan(DEFAULT_SALT);
    let chan_b = env.chan(DEFAULT_SALT + 1);
    env.close_two_phase(&chan_a);
    env.close_two_phase(&chan_b);

    let rent_a = lamports(&env.svm, &chan_a.channel);
    let rent_b = lamports(&env.svm, &chan_b.channel);
    warp_past_close_gate(&mut env.svm, &chan_a.channel);
    warp_past_close_gate(&mut env.svm, &chan_b.channel);
    let payer_before = lamports(&env.svm, &env.payer.pubkey());

    // Both channels share the same recorded rent payer, which is credited
    // twice within the one tx.
    send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[
            build_reclaim_ix(&chan_a.channel, &env.payer.pubkey()),
            build_reclaim_ix(&chan_b.channel, &env.payer.pubkey()),
        ],
    )
    .expect("batched reclaim ok");

    assert_reclaimed(&env.svm, &chan_a.channel);
    assert_reclaimed(&env.svm, &chan_b.channel);
    let payer_after = lamports(&env.svm, &env.payer.pubkey());
    assert_eq!(payer_after - payer_before, rent_a + rent_b);
}

// ===========================================================================
// Reincarnation: `open_slot` is a PDA seed, so an address IS an incarnation.
// After reclaim frees the old address, reopening the same
// (payer, payee, mint, signer, salt) tuple lands at a NEW address — the old
// one can never be re-derived (its open_slot no longer clears the open
// window) — and the dead incarnation's vouchers bind the dead address.

#[test]
fn reincarnation_after_reclaim_lands_at_new_address_and_stale_vouchers_die() {
    let mut env = Env::new(DEPOSIT);
    let chan_a = env.chan(DEFAULT_SALT);
    env.close_two_phase(&chan_a);

    warp_past_close_gate(&mut env.svm, &chan_a.channel);
    send_tx(
        &mut env.svm,
        &env.fee_payer,
        &[],
        &[build_reclaim_ix(&chan_a.channel, &env.payer.pubkey())],
    )
    .expect("reclaim ok");
    assert_reclaimed(&env.svm, &chan_a.channel);

    // (a) Reopen the same (payer, payee, mint, signer, salt) tuple, funded
    // by the phase-1 refund. The reclaim gate forced `clock.slot >
    // chan_a.open_slot + OPEN_SLOT_WINDOW`, so the fresh incarnation's
    // `open_slot` — and therefore its seed set — differs: the channel lands
    // at a NEW address by construction.
    let new_deposit: u64 = 40_000;
    let chan_b = env.chan(DEFAULT_SALT);
    assert!(
        chan_b.open_slot > chan_a.open_slot + OPEN_SLOT_WINDOW,
        "reincarnation slot is past the dead incarnation's window"
    );
    assert_ne!(
        chan_b.channel, chan_a.channel,
        "same tuple + new open_slot seed = new address"
    );
    env.open(&chan_b, new_deposit);
    assert_eq!(
        channel_open_slot(&env.svm, &chan_b.channel),
        chan_b.open_slot
    );

    // (b) A voucher minted for the DEAD incarnation presented against the
    // live one: correctly signed, monotonic, under deposit — but its
    // `channel_id` is the old address, and that address binding is the
    // entire epoch check now.
    let ixs = env.settle_pair_cross(chan_a.channel, chan_b.channel, 1_000);
    expect_custom_err(
        send_tx(&mut env.svm, &env.fee_payer, &[], &ixs),
        PaymentChannelsError::VoucherChannelMismatch,
    );
    read_channel(&env.svm, &chan_b.channel, |ch| {
        assert_eq!(
            ch.settled(),
            0,
            "dead incarnation's voucher must not settle"
        );
    });

    // (c) Settling the dead address itself is just as dead: the account is
    // a system-owned shell, so the owner check fails before voucher logic.
    let ixs = env.settle_pair(&chan_a, 1_000);
    expect_instruction_err(
        send_tx(&mut env.svm, &env.fee_payer, &[], &ixs),
        InstructionError::InvalidAccountOwner,
    );

    // (d) A voucher for the live address settles normally.
    env.settle_to(&chan_b, 2_000);
    read_channel(&env.svm, &chan_b.channel, |ch| {
        assert_eq!(ch.settled(), 2_000, "live incarnation's voucher settles");
    });
}
