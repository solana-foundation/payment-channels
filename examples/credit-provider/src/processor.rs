use borsh::{BorshDeserialize, BorshSerialize};
use payment_channels::{Channel, ChannelStatus, hooks::HookContext, instructions};
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock, rent::Rent},
};
use pinocchio_token::{
    instructions::Transfer,
    state::{Account, Mint},
};

use crate::{Authorization, LEDGER_SEED, LOADER, Ledger, ata_address, hook_state, ledger_address};

fn require(condition: bool) -> ProgramResult {
    if condition {
        Ok(())
    } else {
        Err(ProgramError::InvalidAccountData)
    }
}

fn add(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_add(b).ok_or(ProgramError::ArithmeticOverflow)
}

fn sub(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_sub(b).ok_or(ProgramError::InsufficientFunds)
}

fn load(program: &Address, account: &AccountView) -> Result<Ledger, ProgramError> {
    require(
        account.owned_by(program) && account.is_writable() && account.data_len() == Ledger::LEN,
    )?;
    let ledger = Ledger::try_from_slice(&account.try_borrow()?)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    require(ledger.version == 1 && !ledger.busy)?;
    let owner = Address::new_from_array(ledger.owner);
    let mint = Address::new_from_array(ledger.mint);
    require(ledger_address(program, &owner, &mint).0 == *account.address())?;
    Ok(ledger)
}

fn store(account: &mut AccountView, ledger: &Ledger) -> ProgramResult {
    ledger
        .serialize(&mut &mut account.try_borrow_mut()?[..])
        .map_err(|_| ProgramError::InvalidAccountData)
}

/// Verify the issuer against loader-owned executable/ProgramData state.
/// An arbitrary first caller cannot nominate themselves as the provider.
pub fn initialize(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [
        owner,
        ledger,
        mint,
        executable,
        program_data,
        issuer,
        system,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(owner.is_signer() && owner.is_writable() && issuer.is_signer())?;
    require(*system.address() == pinocchio_system::ID && system.executable())?;
    require(
        executable.address() == program
            && executable.executable()
            && executable.owned_by(&LOADER)
            && program_data.owned_by(&LOADER),
    )?;
    let program_bytes = executable.try_borrow()?;
    // UpgradeableLoaderState::Program (bincode u32 tag, ProgramData address).
    require(
        program_bytes.len() == 36
            && program_bytes[..4] == 2u32.to_le_bytes()
            && program_bytes[4..36] == *program_data.address().as_array(),
    )?;
    let pd = program_data.try_borrow()?;
    // ProgramData: u32 tag, u64 slot, Option<Pubkey> authority, ELF bytes.
    require(
        pd.len() >= 45
            && pd[..4] == 3u32.to_le_bytes()
            && pd[12] == 1
            && pd[13..45] == *issuer.address().as_array(),
    )?;
    drop(pd);
    drop(program_bytes);
    let mint_state = Mint::from_account_view(mint)?;
    require(mint_state.is_initialized())?;
    drop(mint_state);
    let (expected, bump) = ledger_address(program, owner.address(), mint.address());
    require(
        *ledger.address() == expected
            && ledger.is_writable()
            && ledger.owned_by(&pinocchio_system::ID)
            && ledger.data_len() == 0,
    )?;
    let bump_bytes = [bump];
    let seeds = [
        Seed::from(LEDGER_SEED),
        Seed::from(owner.address().as_ref()),
        Seed::from(mint.address().as_ref()),
        Seed::from(&bump_bytes),
    ];
    // Match the channel program's prefund-resistant initialization: a donated
    // lamport must not let an unrelated account block this owner's ledger.
    let rent = Rent::get()?.try_minimum_balance(Ledger::LEN)?;
    let pending = rent.saturating_sub(ledger.lamports());
    if pending > 0 {
        pinocchio_system::instructions::Transfer {
            from: owner,
            to: ledger,
            lamports: pending,
        }
        .invoke()?;
    }
    let signers = [Signer::from(&seeds)];
    pinocchio_system::instructions::Allocate {
        account: ledger,
        space: Ledger::LEN as u64,
    }
    .invoke_signed(&signers)?;
    pinocchio_system::instructions::Assign {
        account: ledger,
        owner: program,
    }
    .invoke_signed(&signers)?;
    store(
        ledger,
        &Ledger {
            version: 1,
            owner: *owner.address().as_array(),
            mint: *mint.address().as_array(),
            issuer: *issuer.address().as_array(),
            ..Ledger::default()
        },
    )
}

fn custody(
    ledger_account: &AccountView,
    ledger: &Ledger,
    vault: &AccountView,
    payer: &AccountView,
    token: &AccountView,
) -> ProgramResult {
    require(
        *token.address() == pinocchio_token::ID
            && token.executable()
            && vault.is_writable()
            && payer.is_writable(),
    )?;
    let mint = Address::new_from_array(ledger.mint);
    let owner = Address::new_from_array(ledger.owner);
    require(
        *vault.address() == ata_address(ledger_account.address(), &mint)
            && *payer.address() == ata_address(&owner, &mint)
            && vault.address() != payer.address(),
    )?;
    let v = Account::from_account_view(vault)?;
    let p = Account::from_account_view(payer)?;
    require(
        v.owner() == ledger_account.address()
            && v.mint() == &mint
            && p.owner() == &owner
            && p.mint() == &mint
            && v.is_initialized()
            && p.is_initialized()
            && !v.is_frozen()
            && !p.is_frozen()
            && !v.is_native()
            && !p.is_native()
            && !v.has_delegate()
            && !v.has_close_authority()
            && !p.has_close_authority()
            && v.amount() >= ledger.credits,
    )
}

fn owner_signed(owner: &AccountView, ledger: &Ledger) -> ProgramResult {
    require(owner.is_signer() && owner.address().as_array() == &ledger.owner)
}

/// Issue credits only after an actual owner-authorized transfer into custody.
pub fn deposit(program: &Address, accounts: &mut [AccountView], amount: u64) -> ProgramResult {
    let [owner, ledger_account, vault, payer, token] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut ledger = load(program, ledger_account)?;
    owner_signed(owner, &ledger)?;
    custody(ledger_account, &ledger, vault, payer, token)?;
    require(amount > 0)?;
    let credits = add(ledger.credits, amount)?;
    let before = Account::from_account_view(vault)?.amount();
    let expected = add(before, amount)?;
    ledger.busy = true;
    store(ledger_account, &ledger)?;
    Transfer::new(payer, vault, owner, amount).invoke()?;
    require(Account::from_account_view(vault)?.amount() == expected)?;
    ledger.credits = credits;
    ledger.busy = false;
    store(ledger_account, &ledger)
}

/// Bind the issuer's policy and the owner's consent to one channel incarnation.
pub fn authorize(
    program: &Address,
    accounts: &mut [AccountView],
    authorization: Authorization,
) -> ProgramResult {
    let [owner, issuer, ledger_account, vault, payer, token] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut ledger = load(program, ledger_account)?;
    owner_signed(owner, &ledger)?;
    require(issuer.is_signer() && issuer.address().as_array() == &ledger.issuer)?;
    custody(ledger_account, &ledger, vault, payer, token)?;
    require(
        !ledger.active
            && authorization.cap > 0
            && authorization.nonce == add(ledger.authorization.nonce, 1)?
            && authorization.expires_at_slot >= Clock::get()?.slot
            && authorization.open_slot <= authorization.expires_at_slot
            && authorization.payee != ledger.owner
            && authorization.payee != [0; 32]
            && authorization.authorized_signer != [0; 32],
    )?;
    let p = Account::from_account_view(payer)?;
    // Exact cap at authorization; no unbounded delegated debit capability.
    require(
        p.delegate() == Some(ledger_account.address()) && p.delegated_amount() == authorization.cap,
    )?;
    drop(p);
    let mint = Address::new_from_array(ledger.mint);
    ledger.channel = *Channel::find_pda(
        owner.address(),
        &Address::new_from_array(authorization.payee),
        &mint,
        &Address::new_from_array(authorization.authorized_signer),
        authorization.salt,
        authorization.open_slot,
    )
    .0
    .as_array();
    ledger.configuration = hook_state(program, owner.address(), &mint).commitment;
    ledger.authorization = authorization;
    ledger.active = true;
    ledger.funded = 0;
    ledger.refunded = 0;
    ledger.last_sequence = 0;
    store(ledger_account, &ledger)
}

pub fn callback(program: &Address, accounts: &mut [AccountView], c: &HookContext) -> ProgramResult {
    let [authority, channel, ledger_account, vault, payer, token] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(
        authority.is_signer()
            && !authority.is_writable()
            && !channel.is_signer()
            && !channel.is_writable()
            && [&*ledger_account, &*vault, &*payer, &*token]
                .iter()
                .all(|a| !a.is_signer()),
    )?;
    let mut ledger = load(program, ledger_account)?;
    require(ledger.active)?;
    custody(ledger_account, &ledger, vault, payer, token)?;
    let a = &ledger.authorization;
    let ch = Channel::from_account(channel)?;
    let expected_channel = Channel::find_pda(
        &ch.payer,
        &ch.payee,
        &ch.mint,
        &ch.authorized_signer,
        ch.salt(),
        ch.open_slot(),
    )
    .0;
    require(
        channel.address() == &expected_channel
            && channel.address().as_array() == &ledger.channel
            && c.channel == ledger.channel
            && c.open_slot == a.open_slot
            && ch.open_slot() == a.open_slot
            && ch.salt() == a.salt
            && c.payer == ledger.owner
            && ch.payer.as_array() == &ledger.owner
            && c.mint == ledger.mint
            && ch.mint.as_array() == &ledger.mint
            && c.payee == a.payee
            && ch.payee.as_array() == &a.payee
            && c.authorized_signer == a.authorized_signer
            && ch.authorized_signer.as_array() == &a.authorized_signer
            && c.distribution_hash == a.distribution_hash
            && ch.distribution_hash == a.distribution_hash
            && c.token_program == *pinocchio_token::ID.as_array()
            && c.configuration == ledger.configuration
            && ch.hooks.commitment == ledger.configuration
            && ch.hooks.in_progress == 1
            && c.sequence == u64::from_le_bytes(ch.hooks.sequence)
            && c.sequence > ledger.last_sequence
            && c.refund_destination == *payer.address().as_array(),
    )?;
    let expected_authority = Address::find_program_address(
        &[
            payment_channels::hooks::AUTHORITY_SEED,
            channel.address().as_ref(),
            &ledger.configuration,
            &[c.phase],
            program.as_ref(),
        ],
        &payment_channels::ID,
    )
    .0;
    require(*authority.address() == expected_authority)?;
    // Verify descriptors themselves, not only the stored commitment.
    let expected = hook_state(program, &ch.payer, &ch.mint);
    for (actual, expected) in ch.hooks.descriptors.iter().zip(expected.descriptors.iter()) {
        require(
            actual.program == expected.program
                && actual.entrypoint == expected.entrypoint
                && actual.account_count == expected.account_count
                && actual.static_len == expected.static_len
                && actual.static_context == expected.static_context,
        )?;
        for (actual, expected) in actual.accounts.iter().zip(expected.accounts.iter()) {
            require(actual.address == expected.address && actual.writable == expected.writable)?;
        }
    }
    let status = ChannelStatus::try_from(ch.status)?;
    let deposit = ch.deposit();
    drop(ch);
    match c.phase {
        0 => pre_fund(
            program,
            ledger_account,
            vault,
            payer,
            &mut ledger,
            c,
            status,
            deposit,
        ),
        3 => post_distribute(
            program,
            ledger_account,
            vault,
            payer,
            &mut ledger,
            c,
            status,
            deposit,
        ),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Recover an authorization that never funded a channel. Both parties consent;
/// the consumed nonce is retained so the canceled authorization cannot replay.
pub fn cancel_unfunded(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [owner, issuer, ledger_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut ledger = load(program, ledger_account)?;
    owner_signed(owner, &ledger)?;
    require(issuer.is_signer() && issuer.address().as_array() == &ledger.issuer)?;
    cancel_unfunded_state(&mut ledger)?;
    store(ledger_account, &ledger)
}

fn cancel_unfunded_state(ledger: &mut Ledger) -> ProgramResult {
    require(
        ledger.active && ledger.funded == 0 && ledger.refunded == 0 && ledger.last_sequence == 0,
    )?;
    ledger.active = false;
    Ok(())
}

fn delegated_for(
    payer: &AccountView,
    ledger: &AccountView,
    amount: u64,
    cap: u64,
) -> ProgramResult {
    let p = Account::from_account_view(payer)?;
    require(
        p.delegate() == Some(ledger.address())
            && p.delegated_amount() >= amount
            && p.delegated_amount() <= cap,
    )
}

fn transfer_signed(
    program: &Address,
    ledger_account: &AccountView,
    ledger: &Ledger,
    from: &AccountView,
    to: &AccountView,
    amount: u64,
) -> ProgramResult {
    let bump = [ledger_address(
        program,
        &Address::new_from_array(ledger.owner),
        &Address::new_from_array(ledger.mint),
    )
    .1];
    let seeds = [
        Seed::from(LEDGER_SEED),
        Seed::from(&ledger.owner),
        Seed::from(&ledger.mint),
        Seed::from(&bump),
    ];
    Transfer::new(from, to, ledger_account, amount).invoke_signed(&[Signer::from(&seeds)])
}

/// Debit credits and move exactly the requested backing into the payer ATA.
/// The surrounding channel instruction consumes that backing before returning.
#[allow(clippy::too_many_arguments)]
pub fn pre_fund(
    program: &Address,
    ledger_account: &mut AccountView,
    vault: &AccountView,
    payer: &AccountView,
    ledger: &mut Ledger,
    c: &HookContext,
    status: ChannelStatus,
    deposit: u64,
) -> ProgramResult {
    require(
        c.executed == 0
            && status == ChannelStatus::Open
            && c.funding_requested > 0
            && c.funding_transferred == 0
            && c.refund_transferred_to_payer == 0
            && c.redirected_principal == 0
            && Clock::get()?.slot <= ledger.authorization.expires_at_slot,
    )?;
    match c.operation {
        instructions::open::DISCRIMINATOR => require(
            ledger.funded == 0
                && ledger.last_sequence == 0
                && c.sequence == 1
                && deposit == 0
                && c.deposit_before == deposit,
        )?,
        instructions::top_up::DISCRIMINATOR => {
            require(ledger.funded > 0 && deposit == ledger.funded && c.deposit_before == deposit)?
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }
    let funded = add(ledger.funded, c.funding_requested)?;
    require(funded <= ledger.authorization.cap)?;
    let credits = sub(ledger.credits, c.funding_requested)?;
    delegated_for(
        payer,
        ledger_account,
        sub(funded, ledger.refunded)?,
        ledger.authorization.cap,
    )?;
    let vault_after = sub(
        Account::from_account_view(vault)?.amount(),
        c.funding_requested,
    )?;
    let payer_after = add(
        Account::from_account_view(payer)?.amount(),
        c.funding_requested,
    )?;
    ledger.busy = true;
    ledger.credits = credits;
    ledger.funded = funded;
    ledger.last_sequence = c.sequence;
    store(ledger_account, ledger)?;
    transfer_signed(
        program,
        ledger_account,
        ledger,
        vault,
        payer,
        c.funding_requested,
    )?;
    require(
        Account::from_account_view(vault)?.amount() == vault_after
            && Account::from_account_view(payer)?.amount() == payer_after,
    )?;
    ledger.busy = false;
    store(ledger_account, ledger)
}

/// Restore credits only after the actual refund has returned to provider custody.
/// Zero-refund callbacks still consume their sequence and terminal binding.
#[allow(clippy::too_many_arguments)]
pub fn post_distribute(
    program: &Address,
    ledger_account: &mut AccountView,
    vault: &AccountView,
    payer: &AccountView,
    ledger: &mut Ledger,
    c: &HookContext,
    status: ChannelStatus,
    deposit: u64,
) -> ProgramResult {
    require(
        c.executed == 1
            && ledger.funded > 0
            && deposit == ledger.funded
            && c.deposit_before == deposit
            && c.deposit_after == deposit
            && c.funding_requested == 0
            && c.funding_transferred == 0
            && c.redirected_principal == 0
            && c.refund_transferred_to_payer == c.refund_due,
    )?;
    let terminal = match c.operation {
        instructions::withdraw_payer::DISCRIMINATOR => {
            require(status == ChannelStatus::Sealed)?;
            false
        }
        instructions::distribute::DISCRIMINATOR => {
            require(matches!(
                status,
                ChannelStatus::Open | ChannelStatus::Sealed
            ))?;
            status == ChannelStatus::Sealed
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    let amount = c.refund_transferred_to_payer;
    let refunded = add(ledger.refunded, amount)?;
    require(refunded <= ledger.funded)?;
    let credits = add(ledger.credits, amount)?;
    let vault_after = add(Account::from_account_view(vault)?.amount(), amount)?;
    let payer_after = sub(Account::from_account_view(payer)?.amount(), amount)?;
    if amount > 0 {
        delegated_for(payer, ledger_account, amount, ledger.authorization.cap)?;
    }
    ledger.busy = true;
    store(ledger_account, ledger)?;
    if amount > 0 {
        transfer_signed(program, ledger_account, ledger, payer, vault, amount)?;
    }
    require(
        Account::from_account_view(vault)?.amount() == vault_after
            && Account::from_account_view(payer)?.amount() == payer_after,
    )?;
    ledger.credits = credits;
    ledger.refunded = refunded;
    ledger.last_sequence = c.sequence;
    // withdrawPayer is not terminal: distribution must still run against the
    // original binding, including when its remaining refund is zero.
    if terminal {
        ledger.active = false;
    }
    ledger.busy = false;
    store(ledger_account, ledger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_unfunded_preserves_nonce_and_backing() {
        let mut ledger = Ledger {
            active: true,
            credits: 100,
            authorization: Authorization {
                nonce: 7,
                ..Authorization::default()
            },
            ..Ledger::default()
        };
        cancel_unfunded_state(&mut ledger).unwrap();
        assert!(!ledger.active);
        assert_eq!(ledger.authorization.nonce, 7);
        assert_eq!(ledger.credits, 100);
        assert!(cancel_unfunded_state(&mut ledger).is_err());
    }

    #[test]
    fn cancellation_never_releases_any_previously_funded_binding() {
        for (funded, refunded, sequence) in [(1, 0, 1), (1, 1, 2), (0, 0, 1), (0, 1, 0)] {
            let mut ledger = Ledger {
                active: true,
                funded,
                refunded,
                last_sequence: sequence,
                ..Ledger::default()
            };
            assert!(cancel_unfunded_state(&mut ledger).is_err());
            assert!(ledger.active);
        }
    }
}
