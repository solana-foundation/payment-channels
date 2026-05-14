use core::mem::MaybeUninit;

use pinocchio::{error::ProgramError, sysvars::clock::Clock};

const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;
const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
const DEFAULT_LAMPORTS_PER_BYTE: u64 = 6_960;

#[inline]
pub fn unix_timestamp() -> Result<i64, ProgramError> {
    legacy_clock().map(|clock| clock.unix_timestamp)
}

#[inline]
pub fn minimum_balance(data_len: usize) -> Result<u64, ProgramError> {
    let data_len = data_len as u64;
    if data_len > MAX_PERMITTED_DATA_LENGTH {
        return Err(ProgramError::InvalidArgument);
    }

    ACCOUNT_STORAGE_OVERHEAD
        .checked_add(data_len)
        .and_then(|size| size.checked_mul(DEFAULT_LAMPORTS_PER_BYTE))
        .ok_or(ProgramError::ArithmeticOverflow)
}

#[inline]
fn legacy_clock() -> Result<Clock, ProgramError> {
    let mut clock = MaybeUninit::<Clock>::uninit();
    let clock_addr = clock.as_mut_ptr().cast::<u8>();

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    #[allow(deprecated)]
    let result = unsafe { pinocchio::syscalls::sol_get_clock_sysvar(clock_addr) };

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    let result = {
        // Host-side process tests do not have runtime sysvars. A zeroed clock
        // keeps those tests deterministic while SBF builds still use the syscall.
        unsafe { clock_addr.write_bytes(0, core::mem::size_of::<Clock>()) };
        pinocchio::SUCCESS
    };

    match result {
        pinocchio::SUCCESS => Ok(unsafe { clock.assume_init() }),
        _ => Err(ProgramError::UnsupportedSysvar),
    }
}
