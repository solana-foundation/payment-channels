/// Basis-point denominator used for distribution shares.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Slot window `K` shared by `open`'s epoch validation and the reclaim
/// gate (1,500 slots — ~10 min at 400 ms/slot; scales with slot duration).
///
/// Sizing: the hard floor is Solana's blockhash validity (150 blocks) —
/// any window >= that never rejects a transaction the runtime could still
/// deliver, at any slot duration, because both are measured in slots. The
/// 10x headroom on top exists for signing flows that escape blockhash
/// expiry via durable nonces (hardware wallets, multisigs, cold storage)
/// and stays comfortable as slot times shrink. Since no token movement is
/// gated (only `reclaim`'s rent recovery waits), the sole cost of a large
/// window is a bounded operator rent float, and hot paths can back-date
/// `open_slot` to reclaim sooner. Expected to be ratcheted DOWN with
/// mainnet data — never up (see below).
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
/// Operational constraint: because the window is measured from the
/// client-chosen `open_slot`, the `open` transaction must be signed AND
/// landed within `K` slots of choosing it (standard transactions are
/// bounded tighter still, by the 150-block blockhash validity; the full
/// window applies to durable-nonce transactions). Flows that miss it must
/// re-derive with a fresh `open_slot` (which, being a PDA seed, also
/// changes the channel address) and re-sign. Only `open` is affected;
/// vouchers and every other instruction carry no such deadline.
///
/// CONSENSUS-CRITICAL: this constant may only ever be DECREASED in future
/// program versions. The proof requires the `K` in force at a close to
/// out-wait the window of any later open at that address; increasing `K`
/// would let a reincarnation reuse an epoch closed under the smaller `K`,
/// re-arming old vouchers.
pub const OPEN_SLOT_WINDOW: u64 = 1_500;

/// Deployment ratchet for [`OPEN_SLOT_WINDOW`]. When shipping a smaller
/// window, lower BOTH constants together. NEVER raise either: every value
/// this ceiling has ever held must remain >= the window of any later
/// deployment, or an address deallocated under the smaller window could
/// become re-derivable and re-arm its old vouchers.
const MAX_DEPLOYED_OPEN_SLOT_WINDOW: u64 = 1_500;

const _: () = assert!(
    OPEN_SLOT_WINDOW <= MAX_DEPLOYED_OPEN_SLOT_WINDOW,
    "OPEN_SLOT_WINDOW may only ever decrease across deployments; raising it \
     re-arms vouchers of channels closed under a smaller window",
);

/// Owner of the treasury ATAs that receive rounding residuals when a channel is
/// closed by the SEALED `distribute`. The treasury ATA is derived as
/// `ATA(TREASURY_OWNER, mint, token_program)` and validated on-chain. The
/// operator must hold the corresponding private key, otherwise accumulated
/// residuals are unspendable.
///
/// The value is per deployment and comes from `vars.treasury_owner` of the
/// channel being built (see `Solex.toml`). `localnet` carries the `0xBEEF`
/// placeholder; a channel without the var does not compile, which replaces the
/// former cluster-feature release gate.
pub const TREASURY_OWNER: pinocchio::Address = pinocchio::Address::new_from_array(
    const_crypto::bs58::decode_pubkey(solex::var!("treasury_owner")),
);
