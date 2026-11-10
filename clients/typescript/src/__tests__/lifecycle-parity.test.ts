import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { address, getAddressDecoder } from '@solana/kit';
import { describe, expect, it } from 'vitest';
import {
  getChannelEncoder,
  getChannelWithHooksEncoder,
  getHookConfigCodec,
  getHookContextCodec,
  getHookContextEncoder,
  getHookDescriptorEncoder,
  getHookStateEncoder,
  getOpenWithHooksInstructionDataEncoder,
} from '../generated/index.js';

const fixture = JSON.parse(
  readFileSync(new URL('../../../../fixtures/lifecycle-v2.json', import.meta.url), 'utf8'),
);
const target = address('BPFLoaderUpgradeab1e11111111111111111111111');

describe('V2 generated wire parity', () => {
  it('retains the documented fixed layouts', () => {
    expect(getChannelEncoder().fixedSize).toBe(256);
    expect(getChannelWithHooksEncoder().fixedSize).toBe(1121);
    expect(getHookDescriptorEncoder().fixedSize).toBe(206);
    expect(getHookStateEncoder().fixedSize).toBe(865);
    expect(getHookContextEncoder().fixedSize).toBe(428);
  });

  it('encodes compact descriptors in the parser order, without a misplaced Vec prefix', () => {
    const codec = getHookConfigCodec();
    const kinds = ['Accounts0', 'Accounts1', 'Accounts2', 'Accounts3', 'Accounts4'] as const;
    for (let count = 0; count <= 4; count++) {
      const config = [
        null,
        {
          program: target,
          entrypoint: [1, 2, 3, 4, 5, 6, 7, 8],
          accounts: {
            __kind: kinds[count],
            staticContext: [9, 10, 11],
            accounts: Array.from({ length: count }, (_, i) => ({
              address: getAddressDecoder().decode(new Uint8Array(32).fill(i + 1)),
              writable: i % 2,
            })),
          },
        },
        null,
        null,
      ];
      const encoded = codec.encode(config);
      expect(Buffer.from(encoded).toString('hex')).toBe(fixture.compact[count]);
      expect(codec.encode(codec.decode(encoded))).toEqual(encoded);
    }
    expect(Array.from(codec.encode([null, null, null, null]))).toEqual([0, 0, 0, 0]);
  });

  it('requires four explicit disabled slots after the V1 opening payload', () => {
    const data = getOpenWithHooksInstructionDataEncoder().encode({
      openWithHooksArgs: {
        salt: 1n,
        deposit: 2n,
        gracePeriod: 3,
        openSlot: 4n,
        recipients: [],
        hookConfig: [null, null, null, null],
      },
    });
    expect(Buffer.from(data).toString('hex')).toBe(fixture.unhookedOpen);
  });

  it('matches the real Rust callback context serialization', () => {
    const bytes = Buffer.from(fixture.callbackContext, 'hex');
    const codec = getHookContextCodec();
    const context = codec.decode(bytes);
    expect(context.sequence).toBe(0x0807060504030201n);
    expect(context.withdrawnBefore).toBe(-42n);
    expect(context.refundTransferredToPayer).toBe(123n);
    expect(context.refundDestination).toEqual(new Array(32).fill(9));
    expect(Buffer.from(codec.encode(context))).toEqual(bytes);
  });

  it('preserves all V1 wire nodes and account metadata while adding hooked APIs', () => {
    const readJson = (path: string) =>
      JSON.parse(readFileSync(new URL(`../../../../${path}`, import.meta.url), 'utf8'));
    const program = readJson('program/payment_channels/idl/payment_channels.json').program;
    const baseline = readJson('fixtures/v1-idl-shapes.json');
    function withoutDocs(value: unknown): unknown {
      if (Array.isArray(value)) return value.map(withoutDocs);
      if (value && typeof value === 'object') {
        return Object.fromEntries(
          Object.entries(value)
            .filter(([key]) => key !== 'docs')
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, child]) => [key, withoutDocs(child)]),
        );
      }
      return value;
    }
    expect(program.publicKey).toBe('CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX');
    for (const group of ['accounts', 'instructions', 'definedTypes']) {
      for (const [name, hash] of Object.entries(baseline[group])) {
        const node = program[group].find((node: { name: string }) => node.name === name);
        expect(node, name).toBeDefined();
        expect(
          createHash('sha256')
            .update(JSON.stringify(withoutDocs(node)))
            .digest('hex'),
          name,
        ).toBe(hash);
      }
    }
  });
});
