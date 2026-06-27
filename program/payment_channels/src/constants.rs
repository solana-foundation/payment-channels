/// Basis-point denominator used for distribution shares.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// The `0xBE 0xEF` × 16 placeholder owner. Fine for localnet/default builds; a
/// `devnet`/`testnet`/`mainnet-beta` build rejects it (gate below), forcing a real owner.
const TREASURY_OWNER_SENTINEL: [u8; 32] = [
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
];

// Per-cluster constants, grouped by chain. Exactly one `cluster` module compiles,
// selected at build time via mutually-exclusive Cargo features (precedence
// mainnet-beta > devnet > testnet > localnet/default). To onboard a new
// per-cluster value, add it to each block. Set the devnet/testnet/mainnet-beta
// `TREASURY_OWNER` to the real owner before deploy, e.g.
// `const_crypto::bs58::decode_pubkey("Your…Owner")`.
#[cfg(feature = "mainnet-beta")]
mod cluster {
    pub const TREASURY_OWNER: [u8; 32] =
        const_crypto::bs58::decode_pubkey("Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP");
}

#[cfg(all(feature = "devnet", not(feature = "mainnet-beta")))]
mod cluster {
    use super::*;
    pub const TREASURY_OWNER: [u8; 32] = TREASURY_OWNER_SENTINEL; // TODO: real devnet owner
}

#[cfg(all(
    feature = "testnet",
    not(feature = "devnet"),
    not(feature = "mainnet-beta")
))]
mod cluster {
    use super::*;
    pub const TREASURY_OWNER: [u8; 32] = TREASURY_OWNER_SENTINEL; // TODO: real testnet owner
}

#[cfg(all(
    not(feature = "mainnet-beta"),
    not(feature = "devnet"),
    not(feature = "testnet")
))]
mod cluster {
    use super::*;
    pub const TREASURY_OWNER: [u8; 32] = TREASURY_OWNER_SENTINEL; // localnet / default placeholder
}

/// Owner of the treasury ATAs that receive rounding residuals when a channel is
/// finalized by `distribute`. The treasury ATA is derived as
/// `ATA(TREASURY_OWNER, mint, token_program)` and validated on-chain. The
/// operator must hold the corresponding private key, otherwise accumulated
/// residuals are unspendable.
pub const TREASURY_OWNER: pinocchio::Address =
    pinocchio::Address::new_from_array(cluster::TREASURY_OWNER);

/// Build-time guard: a devnet/testnet/mainnet-beta build must not ship the placeholder owner.
#[cfg(any(feature = "devnet", feature = "testnet", feature = "mainnet-beta"))]
const _: () = assert!(
    !matches!(cluster::TREASURY_OWNER, TREASURY_OWNER_SENTINEL),
    "TREASURY_OWNER is still the 0xBEEF placeholder; set the real owner before \
     building --features devnet/testnet/mainnet-beta",
);
