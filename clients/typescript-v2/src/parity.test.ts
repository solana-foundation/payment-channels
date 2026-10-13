import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { address, getAddressDecoder } from '@solana/kit';
import { describe, expect, it } from 'vitest';
import {
  getChannelEncoder,
  getHookConfigCodec,
  getHookContextCodec,
  getHookContextEncoder,
  getHookDescriptorEncoder,
  getHookStateEncoder,
  getOpenInstructionDataEncoder,
} from './generated/index.js';

const fixture = JSON.parse(
  readFileSync(new URL('../../../fixtures/lifecycle-v2.json', import.meta.url), 'utf8'),
);
const target = address('BPFLoaderUpgradeab1e11111111111111111111111');

describe('V2 generated wire parity', () => {
  it('retains the documented fixed layouts', () => {
    expect(getChannelEncoder().fixedSize).toBe(1121);
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
    const data = getOpenInstructionDataEncoder().encode({
      openArgs: {
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

  it('preserves every V1 discriminator and changes only the deployment address', () => {
    const readIdl = (name: string) =>
      JSON.parse(
        readFileSync(
          new URL(`../../../program/payment_channels/idl/${name}.json`, import.meta.url),
          'utf8',
        ),
      ).program;
    const v1 = readIdl('payment_channels');
    const v2 = readIdl('payment_channels_v2');
    expect(v1.publicKey).not.toBe(v2.publicKey);
    expect(v2.publicKey).toBe('CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ');
    const discriminators = (program: typeof v1) =>
      program.instructions.map((ix: { name: string; discriminators: unknown }) => [
        ix.name,
        ix.discriminators,
      ]);
    expect(discriminators(v2)).toEqual(discriminators(v1));
    expect(
      createHash('sha256')
        .update(
          readFileSync(
            new URL('../../../program/payment_channels/idl/payment_channels.json', import.meta.url),
          ),
        )
        .digest('hex'),
    ).toBe(fixture.v1IdlSha256);
  });
});
