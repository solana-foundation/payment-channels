//! Blake3 hashing via the BPF syscall.

/// Blake3 digest of `input`. Single source of truth for `open` and `distribute`.
/// 
/// On-chain uses `sol_blake3`. Host-side test builds use the `blake3` dev-dep
/// so unit tests can assert digest determinism / distinctness; non-test host
/// builds panic — there is no silent zero stub to mask digest mismatches.
#[inline]
pub fn blake3(input: &[u8]) -> [u8; 32] {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut out = [0u8; 32];
        let slices: &[&[u8]] = &[input];
        // SAFETY: sol_blake3 fills exactly 32 bytes; each &[u8] is a fat pointer
        // (ptr, len) matching the SolBytes C layout on 64-bit BPF.
        unsafe {
            pinocchio::syscalls::sol_blake3(slices.as_ptr().cast::<u8>(), 1, out.as_mut_ptr());
        }
        out
    }
    #[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), test))]
    {
        ::blake3::hash(input).into()
    }
    #[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), not(test)))]
    {
        let _ = input;
        panic!("sol_blake3 syscall is unavailable on non-BPF targets");
    }
}
