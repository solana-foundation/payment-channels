/// Basis-point denominator used for distribution shares.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// The `0xBE 0xEF` × 16 placeholder treasury owner. Fine for localnet/default
/// builds; a `devnet`/`testnet`/`mainnet-beta` build rejects it (gate below),
/// forcing a real owner.
const TREASURY_OWNER_SENTINEL: [u8; 32] = [
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
];

/// `0x10 0xCA` × 16 ("LOCA") placeholder chain id for localnet/default builds.
/// A `solana-test-validator` mints a random genesis hash per run, so localnet
/// can't bind to a real one; this fixed marker keeps program and SDK voucher
/// derivations consistent in tests. A `devnet`/`testnet`/`mainnet-beta` build
/// rejects it (gate below). The anti-cross-cluster-replay property only matters
/// on real clusters.
const CHAIN_ID_LOCALNET: [u8; 32] = [
    0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA,
    0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA, 0x10, 0xCA,
];

// Per-cluster constants, grouped by chain. Exactly one `cluster` module compiles,
// selected at build time via mutually-exclusive Cargo features (precedence
// mainnet-beta > devnet > testnet > localnet/default). To onboard a new
// per-cluster value, add it to each block. `CHAIN_ID` is the cluster's genesis
// hash — Solana's canonical chain identifier (the basis of CAIP-2
// `solana:<genesis-hash prefix>`); a program has no runtime access to it, so it
// is compiled in. Set the devnet/testnet/mainnet-beta `TREASURY_OWNER` to the
// real owner before deploy, e.g. `const_crypto::bs58::decode_pubkey("Your…Owner")`.
#[cfg(feature = "mainnet-beta")]
mod cluster {
    use super::*;
    pub const TREASURY_OWNER: [u8; 32] = TREASURY_OWNER_SENTINEL; // TODO: real mainnet-beta owner
    /// mainnet-beta genesis hash.
    pub const CHAIN_ID: [u8; 32] =
        const_crypto::bs58::decode_pubkey("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d");
}

#[cfg(all(feature = "devnet", not(feature = "mainnet-beta")))]
mod cluster {
    use super::*;
    pub const TREASURY_OWNER: [u8; 32] = TREASURY_OWNER_SENTINEL; // TODO: real devnet owner
    /// devnet genesis hash.
    pub const CHAIN_ID: [u8; 32] =
        const_crypto::bs58::decode_pubkey("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG");
}

#[cfg(all(
    feature = "testnet",
    not(feature = "devnet"),
    not(feature = "mainnet-beta")
))]
mod cluster {
    use super::*;
    pub const TREASURY_OWNER: [u8; 32] = TREASURY_OWNER_SENTINEL; // TODO: real testnet owner
    /// testnet genesis hash.
    pub const CHAIN_ID: [u8; 32] =
        const_crypto::bs58::decode_pubkey("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY");
}

#[cfg(all(
    not(feature = "mainnet-beta"),
    not(feature = "devnet"),
    not(feature = "testnet")
))]
mod cluster {
    use super::*;
    pub const TREASURY_OWNER: [u8; 32] = TREASURY_OWNER_SENTINEL; // localnet / default placeholder
    pub const CHAIN_ID: [u8; 32] = CHAIN_ID_LOCALNET; // localnet / default placeholder
}

/// Owner of the treasury ATAs that receive rounding residuals when a channel is
/// finalized by `distribute`. The treasury ATA is derived as
/// `ATA(TREASURY_OWNER, mint, token_program)` and validated on-chain.
pub const TREASURY_OWNER: pinocchio::Address =
    pinocchio::Address::new_from_array(cluster::TREASURY_OWNER);

/// This cluster's chain id (genesis hash). Bound into every Ed25519-signed
/// voucher and checked on-chain by `verify_voucher`, so a voucher signed for one
/// cluster cannot be replayed against an identically-addressed channel on another.
pub const CHAIN_ID: pinocchio::Address = pinocchio::Address::new_from_array(cluster::CHAIN_ID);

/// Build-time guard: a devnet/testnet/mainnet-beta build must ship neither placeholder.
#[cfg(any(feature = "devnet", feature = "testnet", feature = "mainnet-beta"))]
const _: () = assert!(
    !matches!(cluster::TREASURY_OWNER, TREASURY_OWNER_SENTINEL),
    "TREASURY_OWNER is still the 0xBEEF placeholder; set the real owner before \
     building --features devnet/testnet/mainnet-beta",
);
#[cfg(any(feature = "devnet", feature = "testnet", feature = "mainnet-beta"))]
const _: () = assert!(
    !matches!(cluster::CHAIN_ID, CHAIN_ID_LOCALNET),
    "CHAIN_ID is still the localnet placeholder; a devnet/testnet/mainnet-beta build \
     must use that cluster's genesis hash",
);
