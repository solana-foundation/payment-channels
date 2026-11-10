//! Shared wire ABI and mechanical callback checks, not provider authorization.
//!
//! This library supplies no entrypoint, allocator, or panic handler. A callback
//! recipient must obtain its expected channel program and configuration from
//! trusted policy, then enforce its own issuer/customer authorization, limits,
//! expiry, replay records, custody, and credit accounting.
#![no_std]

pub mod channel;
pub mod hooks;
pub mod validation;

pub use hooks::{HookContext, HookDescriptor, HookMeta, HookState};

/// The original deployment; callers validating another deployment must supply
/// its independently trusted ID explicitly.
pub const ID: pinocchio::Address =
    solana_address::address!("CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX");

/// The `canary` channel deployment (`Solex.toml`): the hooked build, on devnet
/// and mainnet. It runs the same dual-version runtime as [`ID`].
pub const CANARY_ID: pinocchio::Address =
    solana_address::address!("CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ");

/// Every deployment of the channel program this crate's ABI describes.
pub const KNOWN_DEPLOYMENTS: [pinocchio::Address; 2] = [ID, CANARY_ID];

/// Whether `program` is one of [`KNOWN_DEPLOYMENTS`]. A callback recipient may
/// accept either, but must still bind each channel to the deployment it
/// authorized (a channel PDA is owned only by the program it derives under).
pub fn is_known_deployment(program: &pinocchio::Address) -> bool {
    KNOWN_DEPLOYMENTS.contains(program)
}

/// SHA-256 used by descriptor commitments, identical on host and on-chain.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        let mut out = [0; 32];
        let slices = [input];
        // SAFETY: the syscall reads the single valid slice and writes 32 bytes.
        unsafe {
            pinocchio::syscalls::sol_sha256(slices.as_ptr().cast(), 1, out.as_mut_ptr());
        }
        out
    }
    #[cfg(not(target_os = "solana"))]
    {
        const_crypto::sha2::Sha256::new().update(input).finalize()
    }
}
