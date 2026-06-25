//! SHA-256 hashing via the BPF syscall.

/// SHA-256 digest of `input`. Single source of truth for `open` and `distribute`.
///
/// On-chain uses `sol_sha256` (always-registered; unlike `sol_blake3`, whose
/// feature gate is inactive on every public cluster). Host-side test builds use
/// `const_crypto`'s SHA-256 so unit tests can assert digest determinism /
/// distinctness; non-test host builds panic so missing-syscall mismatches
/// surface immediately.
#[inline]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut out = [0u8; 32];
        let slices: &[&[u8]] = &[input];
        // SAFETY: sol_sha256 fills exactly 32 bytes; each &[u8] is a fat pointer
        // (ptr, len) matching the SolBytes C layout on 64-bit BPF.
        unsafe {
            pinocchio::syscalls::sol_sha256(slices.as_ptr().cast::<u8>(), 1, out.as_mut_ptr());
        }
        out
    }
    #[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), test))]
    {
        const_crypto::sha2::Sha256::new().update(input).finalize()
    }
    #[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), not(test)))]
    {
        let _ = input;
        panic!("sol_sha256 syscall is unavailable on non-BPF targets");
    }
}
