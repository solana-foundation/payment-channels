import { address, createNoopSigner } from '@solana/kit';
import { describe, expect, it } from 'vitest';
import {
  getChannelCodec,
  getChannelWithHooksCodec,
  getDistributeInstructionDataEncoder,
  getDistributeWithHooksInstructionDataEncoder,
  getOpenInstructionDataEncoder,
  getOpenWithHooksInstructionDataEncoder,
  getTopUpInstruction,
  getTopUpWithHooksInstruction,
  getWithdrawPayerInstructionDataEncoder,
  getWithdrawPayerWithHooksInstructionDataEncoder,
  PAYMENT_CHANNELS_PROGRAM_ADDRESS,
} from '../generated/index.js';

describe('same-address additive instruction ABI', () => {
  it('leaves Open1 unchanged and requires explicit OpenWithHooks10', () => {
    const openArgs = { salt: 1n, deposit: 2n, gracePeriod: 3, openSlot: 4n, recipients: [] };
    const legacy = getOpenInstructionDataEncoder().encode({ openArgs });
    expect(Buffer.from(legacy).toString('hex')).toBe(
      '010100000000000000020000000000000003000000040000000000000000000000',
    );
    const hooked = getOpenWithHooksInstructionDataEncoder().encode({
      openWithHooksArgs: { ...openArgs, hookConfig: [null, null, null, null] },
    });
    expect(hooked[0]).toBe(10);
    expect(hooked.slice(1, -4)).toEqual(legacy.slice(1));
    expect(Array.from(hooked.slice(-4))).toEqual([0, 0, 0, 0]);
  });

  it('builds TopUp3 and TopUpWithHooks11 against the same canonical program', () => {
    const key = address('11111111111111111111111111111111');
    const input = {
      payer: createNoopSigner(key),
      channel: key,
      payerTokenAccount: key,
      channelTokenAccount: key,
      mint: key,
      tokenProgram: key,
      topUpArgs: { amount: 42n },
    };
    const legacy = getTopUpInstruction(input);
    const hooked = getTopUpWithHooksInstruction(input);
    expect(legacy.programAddress).toBe(PAYMENT_CHANNELS_PROGRAM_ADDRESS);
    expect(hooked.programAddress).toBe(legacy.programAddress);
    expect(hooked.accounts).toEqual(legacy.accounts);
    expect(Buffer.from(legacy.data).toString('hex')).toBe('032a00000000000000');
    expect(Buffer.from(hooked.data).toString('hex')).toBe('0b2a00000000000000');
  });

  it('adds distinct hooked distribution/refund tags without changing original bytes', () => {
    const args = { distributeArgs: { recipients: [] } };
    expect(Array.from(getDistributeInstructionDataEncoder().encode(args))).toEqual([7, 0, 0, 0, 0]);
    expect(Array.from(getDistributeWithHooksInstructionDataEncoder().encode(args))).toEqual([
      12, 0, 0, 0, 0,
    ]);
    expect(Array.from(getWithdrawPayerInstructionDataEncoder().encode({}))).toEqual([8]);
    expect(Array.from(getWithdrawPayerWithHooksInstructionDataEncoder().encode({}))).toEqual([13]);
  });
});

describe('explicit channel account codecs never downgrade', () => {
  function account(size: number, version: number) {
    const bytes = new Uint8Array(size);
    bytes.set([1, version]);
    return bytes;
  }

  it('roundtrips V1 at exactly 256 bytes and nested V2 at exactly 1121 bytes', () => {
    const v1 = account(256, 1);
    const v2 = account(1121, 2);
    const legacy = getChannelCodec();
    const hooked = getChannelWithHooksCodec();
    expect(legacy.encode(legacy.decode(v1))).toEqual(v1);
    const decoded = hooked.decode(v2);
    expect(decoded.channel.version).toBe(2);
    expect(hooked.encode(decoded)).toEqual(v2);
  });

  it('rejects cross-version, unknown-version, truncated and extended accounts', () => {
    const legacy = getChannelCodec();
    const hooked = getChannelWithHooksCodec();
    for (const [size, version] of [
      [1121, 2],
      [256, 2],
      [256, 3],
      [255, 1],
      [257, 1],
    ]) {
      expect(() => legacy.decode(account(size, version))).toThrow();
    }
    for (const [size, version] of [
      [256, 1],
      [1121, 1],
      [1121, 3],
      [1120, 2],
      [1122, 2],
    ]) {
      expect(() => hooked.decode(account(size, version))).toThrow();
    }
    expect(() => legacy.decode(new Uint8Array(256))).toThrow();
    expect(() => hooked.decode(new Uint8Array(1121))).toThrow();
  });
});
