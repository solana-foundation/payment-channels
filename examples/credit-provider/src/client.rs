//! Host-side builders; addresses use the same type as the on-chain interface.
use alloc::{vec, vec::Vec};
use borsh::BorshSerialize;
use pinocchio::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::{
    AUTHORIZE, Authorization, CANCEL_UNFUNDED, DEPOSIT, INITIALIZE, LOADER, ata_address,
    hook_state, ledger_address,
};

fn meta(address: Address, writable: bool, signer: bool) -> AccountMeta {
    AccountMeta {
        pubkey: (*address.as_array()).into(),
        is_signer: signer,
        is_writable: writable,
    }
}

fn instruction(program: &Address, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: (*program.as_array()).into(),
        accounts,
        data,
    }
}

pub fn initialize(
    program: &Address,
    owner: &Address,
    mint: &Address,
    issuer: &Address,
) -> Instruction {
    let ledger = ledger_address(program, owner, mint).0;
    let program_data = Address::find_program_address(&[program.as_ref()], &LOADER).0;
    instruction(
        program,
        vec![
            meta(*owner, true, true),
            meta(ledger, true, false),
            meta(*mint, false, false),
            meta(*program, false, false),
            meta(program_data, false, false),
            meta(*issuer, false, true),
            meta(pinocchio_system::ID, false, false),
        ],
        vec![INITIALIZE],
    )
}

pub fn deposit(program: &Address, owner: &Address, mint: &Address, amount: u64) -> Instruction {
    let ledger = ledger_address(program, owner, mint).0;
    let mut data = vec![DEPOSIT];
    data.extend_from_slice(&amount.to_le_bytes());
    instruction(
        program,
        vec![
            meta(*owner, false, true),
            meta(ledger, true, false),
            meta(ata_address(&ledger, mint), true, false),
            meta(ata_address(owner, mint), true, false),
            meta(pinocchio_token::ID, false, false),
        ],
        data,
    )
}

pub fn authorize(
    program: &Address,
    owner: &Address,
    mint: &Address,
    issuer: &Address,
    authorization: Authorization,
) -> Instruction {
    let ledger = ledger_address(program, owner, mint).0;
    let mut data = vec![AUTHORIZE];
    authorization.serialize(&mut data).unwrap();
    instruction(
        program,
        vec![
            meta(*owner, false, true),
            meta(*issuer, false, true),
            meta(ledger, true, false),
            meta(ata_address(&ledger, mint), true, false),
            meta(ata_address(owner, mint), true, false),
            meta(pinocchio_token::ID, false, false),
        ],
        data,
    )
}

/// Cancel only an authorization that has never funded a channel. Its nonce is
/// not reset; subsequent authorization must use the next nonce.
pub fn cancel_unfunded(
    program: &Address,
    owner: &Address,
    mint: &Address,
    issuer: &Address,
) -> Instruction {
    instruction(
        program,
        vec![
            meta(*owner, false, true),
            meta(*issuer, false, true),
            meta(ledger_address(program, owner, mint).0, true, false),
        ],
        vec![CANCEL_UNFUNDED],
    )
}

/// Pass this sparse configuration to the existing V2 `open` builder.
pub fn hook_config(program: &Address, owner: &Address, mint: &Address) -> Vec<u8> {
    let state = hook_state(program, owner, mint);
    let mut bytes = Vec::new();
    for d in state.descriptors {
        bytes.push(u8::from(d.enabled()));
        if !d.enabled() {
            continue;
        }
        bytes.extend_from_slice(d.program.as_ref());
        bytes.extend_from_slice(&d.entrypoint);
        bytes.push(d.account_count);
        bytes.push(d.static_len);
        bytes.extend_from_slice(&d.static_context[..d.static_len as usize]);
        for m in &d.accounts[..d.account_count as usize] {
            bytes.extend_from_slice(m.address.as_ref());
            bytes.push(m.writable);
        }
    }
    bytes
}

/// Append to a channel instruction's accounts. `phase` is 0 for open/topUp,
/// 3 for distribute/withdrawPayer. The channel program supplies the channel
/// account itself and makes the scoped capability a signer during CPI.
pub fn hook_tail(
    program: &Address,
    owner: &Address,
    mint: &Address,
    channel: &Address,
    phase: u8,
) -> Vec<AccountMeta> {
    assert!(
        matches!(phase, 0 | 3),
        "only the two configured phases are supported"
    );
    let state = hook_state(program, owner, mint);
    let authority = payment_channel_interface::hooks::hook_authority(
        &payment_channel_interface::ID,
        channel,
        &state.commitment,
        payment_channel_interface::hooks::Phase::try_from(phase).unwrap(),
        program,
    )
    .0;
    let mut accounts = vec![meta(*program, false, false), meta(authority, false, false)];
    accounts.extend(
        state.descriptors[phase as usize]
            .accounts
            .iter()
            .map(|m| meta(m.address, m.writable == 1, false)),
    );
    accounts
}
