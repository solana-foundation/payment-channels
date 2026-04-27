//! Blake3 hashing via the BPF syscall.
//!
//! On-chain uses `sol_blake3`. Off-chain (host builds) this is a stub that
//! returns zeros; host-side tests must compute digests themselves (e.g., via
//! the `blake3` dev-dep) and inject them into fabricated account state.

/// Blake3 digest of `input`.
#[inline]
pub fn blake3(input: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        let mut out = [0u8; 32];
        let slices: [&[u8]; 1] = [input];
        unsafe {
            pinocchio::syscalls::sol_blake3(
                slices.as_ptr() as *const u8,
                slices.len() as u64,
                out.as_mut_ptr(),
            );
        }
        out
    }
    #[cfg(not(target_os = "solana"))]
    {
        let _ = input;
        [0u8; 32]
    }
}
