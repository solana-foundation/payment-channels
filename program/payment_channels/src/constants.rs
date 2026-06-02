/// Basis-point denominator used for distribution shares.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// The `0xBE 0xEF` × 16 placeholder owner. Fine for localnet/default builds; a
/// `devnet`/`mainnet` build rejects it (gate below), forcing a real owner.
const TREASURY_OWNER_SENTINEL: [u8; 32] = [
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
];

// Per-cluster treasury owner, selected at build time via Cargo features (mutually
// exclusive; precedence mainnet > devnet > localnet/default). Set the devnet/mainnet
// branches to their real owners before deploy, e.g.
//   const_crypto::bs58::decode_pubkey("Your…Owner")
#[cfg(feature = "mainnet")]
const TREASURY_OWNER_BYTES: [u8; 32] = TREASURY_OWNER_SENTINEL; // TODO: real mainnet owner
#[cfg(all(feature = "devnet", not(feature = "mainnet")))]
const TREASURY_OWNER_BYTES: [u8; 32] = TREASURY_OWNER_SENTINEL; // TODO: real devnet owner
#[cfg(all(not(feature = "mainnet"), not(feature = "devnet")))]
const TREASURY_OWNER_BYTES: [u8; 32] = TREASURY_OWNER_SENTINEL; // localnet / default placeholder

/// Owner of the treasury ATAs that receive rounding residuals when a channel is
/// finalized by `distribute`. The treasury ATA is derived as
/// `ATA(TREASURY_OWNER, mint, token_program)` and validated on-chain.
pub const TREASURY_OWNER: pinocchio::Address =
    pinocchio::Address::new_from_array(TREASURY_OWNER_BYTES);

/// Build-time guard: a devnet/mainnet build must not ship the placeholder owner.
#[cfg(any(feature = "devnet", feature = "mainnet"))]
const _: () = assert!(
    !matches!(TREASURY_OWNER_BYTES, TREASURY_OWNER_SENTINEL),
    "TREASURY_OWNER is still the 0xBEEF placeholder; set the real owner before \
     building --features devnet/mainnet",
);
