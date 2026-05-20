//! Address Lookup Table helpers for v0-transaction tests.
//!
//! Legacy transactions cap static account keys at ~32. Worst-case `distribute`
//! passes 8 fixed accounts + 32 recipient ATAs = 40 instruction-meta accounts,
//! plus the fee payer and program id (~42 static keys total), so tests at
//! `MAX_DISTRIBUTION_RECIPIENTS = 32` must use v0 + ALT. We inject a
//! pre-warmed ALT directly into the LiteSVM account store rather than driving
//! the ALT program through CPI — the goal is testing `distribute`, not the ALT
//! lifecycle.

use std::borrow::Cow;

use litesvm::LiteSVM;
use solana_account::Account;
use solana_address_lookup_table_interface::{
    program::ID as ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
    state::{AddressLookupTable, LookupTableMeta},
};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{AddressLookupTableAccount, VersionedMessage, v0::Message as MessageV0};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

/// Installs a pre-warmed ALT into `svm`'s account store and warps one slot
/// so it's usable by v0 messages in the same test (the ALT loader requires
/// `current_slot > last_extended_slot`, strict `>`). Returns the ALT pubkey
/// and the `AddressLookupTableAccount` view the v0 compiler needs.
pub fn install_lookup_table(
    svm: &mut LiteSVM,
    addresses: Vec<Pubkey>,
) -> (Pubkey, AddressLookupTableAccount) {
    let alt_key = Pubkey::new_unique();

    let table = AddressLookupTable {
        meta: LookupTableMeta::default(),
        addresses: Cow::Borrowed(&addresses),
    };
    let data = table.serialize_for_tests().expect("ALT serialize");
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());

    svm.set_account(
        alt_key,
        Account {
            lamports,
            data,
            owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("install ALT account");

    svm.warp_to_slot(1);

    (
        alt_key,
        AddressLookupTableAccount {
            key: alt_key,
            addresses,
        },
    )
}

/// Builds and signs a v0 `VersionedTransaction` for `instructions`,
/// packing any keys in `alt` into a single address-table lookup.
/// Optional `prefix` instructions (e.g. compute-budget) are prepended first.
pub fn build_v0_transaction_with_prefix(
    svm: &LiteSVM,
    payer: &Keypair,
    prefix: &[Instruction],
    instructions: &[Instruction],
    alt: &AddressLookupTableAccount,
) -> VersionedTransaction {
    let blockhash = svm.latest_blockhash();
    let mut ixs: Vec<Instruction> = Vec::with_capacity(prefix.len() + instructions.len());
    ixs.extend_from_slice(prefix);
    ixs.extend_from_slice(instructions);
    let message = MessageV0::try_compile(
        &payer.pubkey(),
        &ixs,
        std::slice::from_ref(alt),
        blockhash,
    )
    .expect("compile v0 message");
    VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer])
        .expect("sign v0 transaction")
}
