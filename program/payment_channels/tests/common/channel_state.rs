//! Post-`open` byte mutators for `Channel` fields whose owning instructions
//! are still stubbed (`request_close`, `finalize`, `withdraw_payer`,
//! `settle_and_finalize`). Each helper is the minimum surface the
//! `distribute` suite needs to reach a target state once those ixs are
//! filled in, every call site here becomes `program.<ix>(...)` and these
//! helpers can be deleted.
//!
//! Field offsets mirror the `#[repr(C)]` layout of `Channel` in
//! `state/channel.rs:60` and the ordering written by `Channel::init_at`
//! (`state/channel.rs:232`).

#![allow(dead_code)]

use litesvm::LiteSVM;
use solana_pubkey::Pubkey;

const STATUS_OFFSET: usize = 3;
const PAID_OUT_OFFSET: usize = 28;
const PAYER_WITHDRAWN_AT_OFFSET: usize = 44;

fn mutate<F: FnOnce(&mut Vec<u8>)>(svm: &mut LiteSVM, channel: &Pubkey, f: F) {
    let mut acct = svm.get_account(channel).expect("channel exists");
    f(&mut acct.data);
    svm.set_account(*channel, acct).expect("overwrite channel");
}

// TODO(close-path): replace with `request_close` / `finalize`.
pub fn set_status(svm: &mut LiteSVM, channel: &Pubkey, status: u8) {
    mutate(svm, channel, |data| data[STATUS_OFFSET] = status);
}

// TODO(close-path): drive via `distribute` chaining once `Finalized` is
// reachable without a stubbed `finalize`.
pub fn set_paid_out(svm: &mut LiteSVM, channel: &Pubkey, paid_out: u64) {
    mutate(svm, channel, |data| {
        data[PAID_OUT_OFFSET..PAID_OUT_OFFSET + 8].copy_from_slice(&paid_out.to_le_bytes());
    });
}

// TODO(close-path): replace with `withdraw_payer`.
pub fn set_payer_withdrawn_at(svm: &mut LiteSVM, channel: &Pubkey, ts: i64) {
    mutate(svm, channel, |data| {
        data[PAYER_WITHDRAWN_AT_OFFSET..PAYER_WITHDRAWN_AT_OFFSET + 8]
            .copy_from_slice(&ts.to_le_bytes());
    });
}
