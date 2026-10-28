// Independently spell out the documented compact bytes, not generated codecs.
// Both generated clients consume this fixture. Run explicitly when intentionally
// changing the V2 ABI.
import { mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../clients/typescript/package.json', import.meta.url));
const { getAddressEncoder } = require('@solana/kit');
const target = getAddressEncoder().encode('BPFLoaderUpgradeab1e11111111111111111111111');
const compact = Array.from({ length: 5 }, (_, count) =>
  Buffer.concat([
    Buffer.from([0, 1]), // disabled preFund, enabled postFund
    target,
    Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]),
    Buffer.from([count, 3, 9, 10, 11]),
    ...Array.from({ length: count }, (_, i) =>
      Buffer.concat([Buffer.alloc(32, i + 1), Buffer.from([i % 2])]),
    ),
    Buffer.from([0, 0]), // disabled distribution pair
  ]).toString('hex'),
);
const open = Buffer.alloc(37); // discriminator + 28-byte header + u32 count + four slots
open[0] = 10;
open.writeBigUInt64LE(1n, 1);
open.writeBigUInt64LE(2n, 9);
open.writeUInt32LE(3, 17);
open.writeBigUInt64LE(4n, 21);
const context = Buffer.alloc(428);
context.set([1, 3, 7, 1]);
context.writeBigUInt64LE(0x0807060504030201n, 36);
context.writeBigInt64LE(-42n, 300);
context.writeBigUInt64LE(123n, 348);
context.fill(9, 396);
const fixture = {
  description:
    'Compact slots [disabled, enabled, disabled, disabled], account counts 0..4; static bytes 090a0b; unique extras [01;32]..[04;32].',
  compact,
  unhookedOpen: open.toString('hex'),
  callbackContext: context.toString('hex'),
};
mkdirSync(new URL('../fixtures/', import.meta.url), { recursive: true });
writeFileSync(
  new URL('../fixtures/lifecycle-v2.json', import.meta.url),
  `${JSON.stringify(fixture, null, 2)}\n`,
);
