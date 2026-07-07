import type { Address } from '@solana/kit';
import { describe, expect, it } from 'vitest';
import {
  getOpenArgsEncoder,
  getTopUpArgsEncoder,
  getVoucherArgsDecoder,
  getVoucherArgsEncoder,
} from '../generated/index.js';
import { getI64Encoder, getU64Encoder } from '../safe-codecs.js';

// Any valid base58 address works; system program is the easiest to grab.
const SYSTEM_ADDR = '11111111111111111111111111111111' as Address;

// Domain-separation prefix of the voucher payload: tag 'V' + version 0x01.
const MAGIC = [0x56, 0x01];

describe('safe u64/i64 encoders runtime-reject lossy JS numbers', () => {
  it('throws TypeError on cumulativeAmount above 2^53-1 passed as number', () => {
    const encoder = getVoucherArgsEncoder();
    // TS blocks this, but JS callers can still pass a raw number.
    // The error message should mention bigint so the caller knows what to do.
    expect(() =>
      encoder.encode({
        magic: MAGIC,
        channelId: SYSTEM_ADDR,
        cumulativeAmount: 9007199254740993 as unknown as bigint,
        expiresAt: 0n,
      }),
    ).toThrow(
      expect.objectContaining({
        constructor: TypeError,
        message: expect.stringMatching(/bigint/i),
      }),
    );
  });

  it('produces distinct images for 2^53 and 2^53 + 1 (regression for the SOLA4-2 root cause)', () => {
    const encoder = getVoucherArgsEncoder();
    const a = encoder.encode({
      magic: MAGIC,
      channelId: SYSTEM_ADDR,
      cumulativeAmount: 2n ** 53n,
      expiresAt: 0n,
    });
    const b = encoder.encode({
      magic: MAGIC,
      channelId: SYSTEM_ADDR,
      cumulativeAmount: 2n ** 53n + 1n,
      expiresAt: 0n,
    });
    expect(a.length).toBe(50);
    expect(b.length).toBe(50);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('round-trips bigint cumulativeAmount through encoder/decoder as bigint', () => {
    const bytes = getVoucherArgsEncoder().encode({
      magic: MAGIC,
      channelId: SYSTEM_ADDR,
      cumulativeAmount: 100n,
      expiresAt: 0n,
    });
    const decoded = getVoucherArgsDecoder().decode(bytes);
    expect(decoded.cumulativeAmount).toBe(100n);
    // Should come back as bigint, not number.
    expect(typeof decoded.cumulativeAmount).toBe('bigint');
  });

  it('accepts safe-integer JS number at runtime and matches bigint encoding', () => {
    const encoder = getVoucherArgsEncoder();
    const fromNumber = encoder.encode({
      magic: MAGIC,
      channelId: SYSTEM_ADDR,
      cumulativeAmount: 100 as unknown as bigint,
      expiresAt: 0n,
    });
    const fromBigint = encoder.encode({
      magic: MAGIC,
      channelId: SYSTEM_ADDR,
      cumulativeAmount: 100n,
      expiresAt: 0n,
    });
    expect(Buffer.from(fromNumber).equals(Buffer.from(fromBigint))).toBe(true);
  });

  it('accepts negative i64 expiresAt and rejects overflow', () => {
    const encoder = getVoucherArgsEncoder();
    // -1n is valid i64
    expect(() =>
      encoder.encode({
        magic: MAGIC,
        channelId: SYSTEM_ADDR,
        cumulativeAmount: 0n,
        expiresAt: -1n,
      }),
    ).not.toThrow();
    // 2^63 overflows signed i64
    expect(() =>
      encoder.encode({
        magic: MAGIC,
        channelId: SYSTEM_ADDR,
        cumulativeAmount: 0n,
        expiresAt: 2n ** 63n,
      }),
    ).toThrow(RangeError);
  });

  it('rejects negative u64 and u64 overflow at the raw encoder', () => {
    const u64 = getU64Encoder();
    expect(() => u64.encode(-1n)).toThrow(RangeError);
    expect(() => u64.encode(2n ** 64n)).toThrow(RangeError);
  });

  it('accepts the inclusive u64 boundaries (0n and 2^64 - 1)', () => {
    // Both endpoints inclusive; catches off-by-one in the range check.
    const u64 = getU64Encoder();
    expect(() => u64.encode(0n)).not.toThrow();
    expect(() => u64.encode(2n ** 64n - 1n)).not.toThrow();
  });

  it('also reaches the i64 raw encoder for direct callers', () => {
    const i64 = getI64Encoder();
    // sanity check
    expect(() => i64.encode(0n)).not.toThrow();
    // unsafe number
    expect(() => i64.encode(9007199254740993 as unknown as bigint)).toThrow(TypeError);
  });

  it('accepts the inclusive i64 boundaries and rejects one past either side', () => {
    const i64 = getI64Encoder();
    // Both i64 endpoints valid; one past either side overflows.
    expect(() => i64.encode(-(2n ** 63n))).not.toThrow();
    expect(() => i64.encode(2n ** 63n - 1n)).not.toThrow();
    expect(() => i64.encode(-(2n ** 63n) - 1n)).toThrow(RangeError);
    expect(() => i64.encode(2n ** 63n)).toThrow(RangeError);
  });

  it('rejects unsafe-integer numbers in OpenArgs.deposit (u64-rich coverage)', () => {
    const encoder = getOpenArgsEncoder();
    expect(() =>
      encoder.encode({
        salt: 0n,
        deposit: 9007199254740993 as unknown as bigint,
        gracePeriod: 0,
        openSlot: 0n,
        recipients: [],
      }),
    ).toThrow(TypeError);
  });

  it('rejects unsafe-integer salt in OpenArgs', () => {
    const encoder = getOpenArgsEncoder();
    expect(() =>
      encoder.encode({
        salt: 9007199254740993 as unknown as bigint,
        deposit: 0n,
        gracePeriod: 0,
        openSlot: 0n,
        recipients: [],
      }),
    ).toThrow(TypeError);
  });

  it('rejects unsafe-integer TopUpArgs.amount', () => {
    const encoder = getTopUpArgsEncoder();
    expect(() => encoder.encode({ amount: 9007199254740993 as unknown as bigint })).toThrow(
      TypeError,
    );
  });

  // (The former SettleAndSealArgs voucher-embedding tests were removed:
  // `settleAndSeal` no longer carries a voucher in its instruction data —
  // the voucher rides in the bundled Ed25519 precompile ix. Voucher numeric
  // safety is covered directly via getVoucherArgsEncoder above, which is the
  // encoder the off-chain signer uses to build that precompile payload.)
});
