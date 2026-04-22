//! Align-1 zero-copy cast infrastructure.
//!
//! Implementers store multi-byte primitives as `[u8; N]` byte arrays (with
//! `from_le_bytes` / `to_le_bytes` accessors) so the struct's alignment is 1.
//! [`load`] / [`load_mut`] then cast any source slice to `&T` / `&mut T`
//! without alignment concerns.

use pinocchio::error::ProgramError;

/// Marker for types castable from a raw byte slice.
///
/// # Safety
///
/// Implementers must guarantee:
/// - `align_of::<Self>() == 1` (enforced at every [`load`] call site by a
///   `const { assert!(...) }`).
/// - `size_of::<Self>() == Self::LEN` and the struct contains no implicit
///   padding bytes — i.e. every field is itself align-1.
pub unsafe trait Transmutable {
    /// On-wire byte length of the type.
    const LEN: usize;
}

/// Reinterpret `bytes` as `&T`. Validates length only and alignment.
///
/// # Safety
///
/// Caller must ensure `bytes` is a valid bit-pattern for `T`. The `Transmutable`
/// impl guarantees align-1 and no padding, so any `T::LEN`-sized byte sequence
/// is a valid `T` as long as its fields satisfy `T`'s own invariants.
#[inline(always)]
pub unsafe fn load<T: Transmutable>(bytes: &[u8]) -> Result<&T, ProgramError> {
    const {
        assert!(
            core::mem::align_of::<T>() == 1,
            "Transmutable types must have alignment 1",
        );
    };
    if bytes.len() != T::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(unsafe { &*(bytes.as_ptr() as *const T) })
}

/// Reinterpret `bytes` as `&mut T`. Validates length only and alignment.
///
/// # Safety
///
/// Same contract as [`load`]: caller must ensure `bytes` is a valid bit-pattern
/// for `T`. Writes through the returned reference must preserve `T`'s invariants.
#[inline(always)]
pub unsafe fn load_mut<T: Transmutable>(bytes: &mut [u8]) -> Result<&mut T, ProgramError> {
    const {
        assert!(
            core::mem::align_of::<T>() == 1,
            "Transmutable types must have alignment 1",
        );
    };
    if bytes.len() != T::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(unsafe { &mut *(bytes.as_mut_ptr() as *mut T) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Debug)]
    struct Sample {
        tag: u8,
        amount: [u8; 8],
        flag: u8,
    }

    unsafe impl Transmutable for Sample {
        const LEN: usize = 10;
    }

    #[test]
    fn load_round_trips_aligned_fields() {
        let mut bytes = [0u8; Sample::LEN];
        bytes[0] = 0xAB;
        bytes[1..9].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[9] = 0x01;

        let s = unsafe { load::<Sample>(&bytes) }.expect("load");
        assert_eq!(s.tag, 0xAB);
        assert_eq!(u64::from_le_bytes(s.amount), u64::MAX);
        assert_eq!(s.flag, 0x01);
    }

    #[test]
    fn load_rejects_wrong_length() {
        let bytes = [0u8; Sample::LEN - 1];
        let err = unsafe { load::<Sample>(&bytes) }.unwrap_err();
        assert_eq!(err, ProgramError::InvalidAccountData);
    }

    #[test]
    fn load_mut_writes_through_to_buffer() {
        let mut bytes = [0u8; Sample::LEN];
        {
            let s = unsafe { load_mut::<Sample>(&mut bytes) }.expect("load_mut");
            s.tag = 0x42;
            s.amount = 1234u64.to_le_bytes();
        }
        assert_eq!(bytes[0], 0x42);
        assert_eq!(u64::from_le_bytes(bytes[1..9].try_into().unwrap()), 1234);
    }

    #[test]
    fn load_zero_size_buffer_works_for_zero_len_type() {
        #[repr(C)]
        struct Empty;
        unsafe impl Transmutable for Empty {
            const LEN: usize = 0;
        }
        let bytes: [u8; 0] = [];
        let _ = unsafe { load::<Empty>(&bytes) }.expect("load");
    }
}
