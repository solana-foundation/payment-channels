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
    let attack_phase = record[3];
    let amount = u32::from_le_bytes(record[4..8].try_into().unwrap()) as u64;
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
    } else if mode >= 3 && phase == attack_phase {
        // Exactly four descriptor accounts: recorder, source, destination (or
        // mint), token program. The scoped capability is a real SPL delegate,
        // close authority or freeze authority installed by the test owner.
        let [source, destination, program] = extras else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        use pinocchio::instruction::{InstructionAccount as Meta, InstructionView};
        let mut payload = [0u8; 35];
        let length = match mode {
            3 => {
                payload[0] = 3; // Transfer
                payload[1..9].copy_from_slice(&amount.to_le_bytes());
                9
            }
            4 => {
                payload[0] = 6; // SetAuthority(CloseAccount)
                payload[1] = 3;
                payload[2] = 1;
                payload[3..35].copy_from_slice(destination.address().as_ref());
                35
            }
            5 => {
                payload[0] = 10;
                1
            } // FreezeAccount
            6 => {
                payload[0] = 9;
                1
            } // CloseAccount
            _ => return Err(ProgramError::InvalidInstructionData),
        };
        let metas = [
            Meta::writable(source.address()),
            if mode == 5 {
                Meta::readonly(destination.address())
            } else {
                Meta::writable(destination.address())
            },
            Meta::readonly_signer(authority.address()),
        ];
        if mode == 4 {
            pinocchio::cpi::invoke(
                &InstructionView {
                    program_id: program.address(),
                    accounts: &[metas[0].clone(), metas[2].clone()],
                    data: &payload[..length],
                },
                &[source, &*authority, program],
            )?;
        } else {
            pinocchio::cpi::invoke(
                &InstructionView {
                    program_id: program.address(),
                    accounts: &metas,
                    data: &payload[..length],
                },
                &[source, destination, &*authority, program],
            )?;
        }
        // No self-rejection: parent invariants must reject AFTER this success.
    }
    Ok(())
}
