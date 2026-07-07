/// Basis-point denominator used for distribution shares.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Slot window `K` shared by `open`'s epoch validation and `distribute`'s
/// terminal-close gate (~60 s at 400 ms/slot).
///
/// `open` requires the client-supplied epoch to satisfy
/// `open_slot <= clock.slot && clock.slot - open_slot <= K` (future slots
/// strictly rejected). The SEALED `distribute` of a v2 channel may fully
/// deallocate the PDA only once `clock.slot > open_slot + K`.
///
/// Uniqueness proof: incarnation N closes at slot `C > open_slot_N + K`; any
/// reincarnation at the same seeds opens at `L >= C` and the open window
/// forces its epoch to `>= L - K >= C - K > open_slot_N`. So
/// `(address, open_slot)` is strictly increasing across incarnations forever
/// — for any client behavior inside the window, including adversarial — and
/// an old voucher can never match a later incarnation's epoch.
///
/// CONSENSUS-CRITICAL: this constant may only ever be DECREASED in future
/// program versions. The proof requires the `K` in force at a close to
/// out-wait the window of any later open at that address; increasing `K`
/// would let a reincarnation reuse an epoch closed under the smaller `K`,
/// re-arming old vouchers.
pub const OPEN_SLOT_WINDOW: u64 = 150;

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
/// closed by the SEALED `distribute`. The treasury ATA is derived as
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
