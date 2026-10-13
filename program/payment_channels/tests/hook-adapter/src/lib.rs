//! SBF-only failure-injecting callback fixture, never deploy to a cluster.
#![no_std]
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

pinocchio::program_entrypoint!(process);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

fn process(id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if data.len() != 437 || &data[..8] != b"record!!" || data[8] != 1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [authority, channel, recorder, extras @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer()
        || authority.is_writable()
        || channel.is_signer()
        || channel.is_writable()
        || extras.iter().any(AccountView::is_signer)
        || !recorder.owned_by(id)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let phase = data[9];
    // The outer instruction tags are 10–13; callback economic tags stay stable.
    if !matches!((phase, data[10]), (0 | 1, 1 | 3) | (2 | 3, 7 | 8)) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (expected, _) = Address::find_program_address(
        &[
            b"channel_hook",
            channel.address().as_ref(),
            &data[188..220],
            &[phase],
            id.as_ref(),
        ],
        channel.owner(),
    );
    if authority.address() != &expected || &data[12..44] != channel.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }
    let channel_data = channel.try_borrow()?;
    if channel_data.len() != 1121 || channel_data.get(256) != Some(&1) {
        return Err(ProgramError::InvalidAccountData);
    }
    drop(channel_data);
    let mut record = recorder.try_borrow_mut()?;
    let count = record[1] as usize;
    let start = 8 + count * 428;
    record[start..start + 428].copy_from_slice(&data[8..436]);
    record[1] += 1;
    // Mutate first, then fail: transaction rollback must erase this write too.
    if record[0] == phase + 1 {
        return Err(ProgramError::Custom(700 + phase as u32));
    }
    let mode = record[2];
    drop(record);
    if mode == 1 {
        let program = &extras[1];
        pinocchio::cpi::invoke(
            &pinocchio::instruction::InstructionView {
                program_id: program.address(),
                accounts: &[pinocchio::instruction::InstructionAccount::readonly(
                    channel.address(),
                )],
                data: &[9], // Reclaim: blocked by runtime reentry or channel guard.
            },
            &[&*channel, program],
        )?;
    } else if mode == 2 {
        let program = &extras[1];
        let mint = &extras[2];
        pinocchio::cpi::invoke(
            &pinocchio::instruction::InstructionView {
                program_id: program.address(),
                accounts: &[pinocchio::instruction::InstructionAccount::readonly(
                    mint.address(),
                )],
                data: &[21], // SPL Token GetAccountDataSize, real depth-three token CPI.
            },
            &[mint, program],
        )?;
    }
    Ok(())
}
