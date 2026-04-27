/// SPL Token (classic) program ID.
pub const SPL_TOKEN_PROGRAM_ID: pinocchio::Address = pinocchio_token::ID;

/// SPL Token-2022 program ID.
pub const TOKEN_2022_PROGRAM_ID: pinocchio::Address = pinocchio_token_2022::ID;

/// Associated-Token-Account program ID.
pub const ATA_PROGRAM_ID: pinocchio::Address = pinocchio_associated_token_account::ID;

/// Owner of the treasury ATAs that receive rounding residuals from `distribute`.
/// TODO Placeholder — **replace before mainnet deploy**. The treasury ATA is derived
/// as `ATA(TREASURY_OWNER, mint, token_program)` and validated on-chain.
pub const TREASURY_OWNER: pinocchio::Address = pinocchio::Address::new_from_array([
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
]);
