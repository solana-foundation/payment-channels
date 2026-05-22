/// Basis-point denominator used for distribution shares.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Owner of the treasury ATAs that receive rounding residuals when a channel
/// is finalized by `distribute`.
/// TODO Placeholder — **replace before mainnet deploy**. The treasury ATA is derived
/// as `ATA(TREASURY_OWNER, mint, token_program)` and validated on-chain.
pub const TREASURY_OWNER: pinocchio::Address = pinocchio::Address::new_from_array([
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
]);
