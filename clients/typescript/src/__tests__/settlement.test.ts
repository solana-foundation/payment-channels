import {
  type Address,
  generateKeyPair,
  getAddressEncoder,
  getAddressFromPublicKey,
  verifySignature,
} from '@solana/kit';
import { describe, expect, it } from 'vitest';
import {
  PAYMENT_CHANNELS_PROGRAM_ADDRESS,
  SETTLE_DISCRIMINATOR,
  SETTLE_METERED_DISCRIMINATOR,
} from '../generated/index.js';
import {
  buildSettleMeteredTransaction,
  buildSettleTransaction,
  CAP_VOUCHER_SIZE,
  CLAIM_VOUCHER_SIZE,
  ED25519_PROGRAM_ADDRESS,
  encodeCapVoucher,
  encodeClaimVoucher,
  encodeVoucher,
  getEd25519VerifyInstruction,
  getSettleInstructions,
  getSettleMeteredInstructions,
  SYSVAR_INSTRUCTIONS_ADDRESS,
  signVoucherMessage,
  VOUCHER_SIZE,
} from '../settlement.js';

const CHANNEL = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' as Address;
const OPERATOR = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL' as Address;
const FEE_PAYER = '11111111111111111111111111111111' as Address;

function le64(value: bigint): number[] {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt.asUintN(64, value), true);
  return [...bytes];
}

async function signedPair() {
  const [client, operator] = await Promise.all([generateKeyPair(), generateKeyPair()]);
  const cap = await signVoucherMessage(
    client,
    encodeCapVoucher({
      channelId: CHANNEL,
      capCumulative: 1_000n,
      operator: await getAddressFromPublicKey(operator.publicKey),
    }),
  );
  const claim = await signVoucherMessage(
    operator,
    encodeClaimVoucher({ channelId: CHANNEL, claimCumulative: 500n }),
  );
  return { cap, claim };
}

async function signedVoucher() {
  return signVoucherMessage(
    await generateKeyPair(),
    encodeVoucher({ channelId: CHANNEL, cumulativeAmount: 500n }),
  );
}

describe('v1 voucher encoder matches the program layout', () => {
  it('encodes the voucher as magic || channel || cumulative || expires_at', () => {
    const bytes = encodeVoucher({
      channelId: CHANNEL,
      cumulativeAmount: 0x0102030405060708n,
      expiresAt: 1_700_000_000n,
    });
    expect(bytes.length).toBe(VOUCHER_SIZE);
    expect([...bytes]).toEqual([
      0x56,
      0x01,
      ...getAddressEncoder().encode(CHANNEL),
      ...le64(0x0102030405060708n),
      ...le64(1_700_000_000n),
    ]);
  });

  it('defaults expiresAt to 0 (no expiry)', () => {
    const bytes = encodeVoucher({ channelId: CHANNEL, cumulativeAmount: 1n });
    expect([...bytes.slice(42, 50)]).toEqual(le64(0n));
  });
});

describe('metered voucher encoders match the program layout', () => {
  it('encodes the cap as magic || channel || cap || expires_at || operator', () => {
    const bytes = encodeCapVoucher({
      channelId: CHANNEL,
      capCumulative: 0x0102030405060708n,
      expiresAt: -1n,
      operator: OPERATOR,
    });
    const address = getAddressEncoder();
    expect(bytes.length).toBe(CAP_VOUCHER_SIZE);
    expect([...bytes]).toEqual([
      0x56,
      0x03,
      ...address.encode(CHANNEL),
      ...le64(0x0102030405060708n),
      ...le64(-1n),
      ...address.encode(OPERATOR),
    ]);
  });

  it('encodes the claim as magic || channel || claim || expires_at', () => {
    const bytes = encodeClaimVoucher({
      channelId: CHANNEL,
      claimCumulative: 500n,
      expiresAt: 1_700_000_000n,
    });
    expect(bytes.length).toBe(CLAIM_VOUCHER_SIZE);
    expect([...bytes]).toEqual([
      0x56,
      0x04,
      ...getAddressEncoder().encode(CHANNEL),
      ...le64(500n),
      ...le64(1_700_000_000n),
    ]);
  });

  it('defaults expiresAt to 0 (no expiry)', () => {
    const bytes = encodeClaimVoucher({ channelId: CHANNEL, claimCumulative: 1n });
    expect([...bytes.slice(42, 50)]).toEqual(le64(0n));
  });
});

describe('getEd25519VerifyInstruction', () => {
  it('uses the canonical single-signature inline layout', async () => {
    const { cap } = await signedPair();
    const ix = getEd25519VerifyInstruction(cap);
    const data = ix.data as Uint8Array;

    expect(ix.programAddress).toBe(ED25519_PROGRAM_ADDRESS);
    expect(data.length).toBe(112 + CAP_VOUCHER_SIZE);
    // num_signatures, padding, then seven u16 LE offsets:
    // signature 48, pubkey 16, message 112, size 82, every index u16::MAX.
    expect([...data.slice(0, 16)]).toEqual([
      1, 0, 48, 0, 0xff, 0xff, 16, 0, 0xff, 0xff, 112, 0, 82, 0, 0xff, 0xff,
    ]);
    expect([...data.slice(16, 48)]).toEqual([...getAddressEncoder().encode(cap.signer)]);
    expect([...data.slice(48, 112)]).toEqual([...cap.signature]);
    expect([...data.slice(112)]).toEqual([...cap.message]);
  });

  it('signs the exact message bytes', async () => {
    const keyPair = await generateKeyPair();
    const message = encodeClaimVoucher({ channelId: CHANNEL, claimCumulative: 7n });
    const signed = await signVoucherMessage(keyPair, message);
    expect(await verifySignature(keyPair.publicKey, signed.signature, message)).toBe(true);
  });
});

describe('getSettleInstructions', () => {
  it('emits [ed25519(voucher), settle]', async () => {
    const voucher = await signedVoucher();
    const [voucherIx, settleIx] = getSettleInstructions({ channel: CHANNEL, voucher });

    expect(voucherIx.programAddress).toBe(ED25519_PROGRAM_ADDRESS);
    expect((voucherIx.data as Uint8Array).length).toBe(112 + VOUCHER_SIZE);
    expect([...(settleIx.data as Uint8Array)]).toEqual([SETTLE_DISCRIMINATOR]);
    expect(settleIx.accounts?.map((a) => a.address)).toEqual([
      CHANNEL,
      SYSVAR_INSTRUCTIONS_ADDRESS,
    ]);
  });

  it('rejects a cap passed as the voucher', async () => {
    const { cap } = await signedPair();
    expect(() => getSettleInstructions({ channel: CHANNEL, voucher: cap })).toThrow(RangeError);
  });

  it('rejects a claim passed as the voucher', async () => {
    const { claim } = await signedPair();
    expect(() => getSettleInstructions({ channel: CHANNEL, voucher: claim })).toThrow(TypeError);
  });
});

describe('buildSettleTransaction', () => {
  it('puts pre-instructions before the voucher', async () => {
    const voucher = await signedVoucher();
    const pre = { programAddress: FEE_PAYER, data: new Uint8Array([9]) };
    const message = buildSettleTransaction({
      channel: CHANNEL,
      voucher,
      feePayer: FEE_PAYER,
      lifetime: { blockhash: FEE_PAYER as never, lastValidBlockHeight: 0n },
      preInstructions: [pre],
    });

    expect(message.version).toBe(0);
    expect(message.feePayer.address).toBe(FEE_PAYER);
    expect(message.instructions.map((ix) => ix.programAddress)).toEqual([
      FEE_PAYER,
      ED25519_PROGRAM_ADDRESS,
      PAYMENT_CHANNELS_PROGRAM_ADDRESS,
    ]);
  });
});

describe('getSettleMeteredInstructions', () => {
  it('emits [ed25519(cap), ed25519(claim), settleMetered]', async () => {
    const { cap, claim } = await signedPair();
    const [capIx, claimIx, settleIx] = getSettleMeteredInstructions({
      channel: CHANNEL,
      cap,
      claim,
    });

    expect(capIx.programAddress).toBe(ED25519_PROGRAM_ADDRESS);
    expect((capIx.data as Uint8Array).length).toBe(112 + CAP_VOUCHER_SIZE);
    expect(claimIx.programAddress).toBe(ED25519_PROGRAM_ADDRESS);
    expect((claimIx.data as Uint8Array).length).toBe(112 + CLAIM_VOUCHER_SIZE);
    expect([...(settleIx.data as Uint8Array)]).toEqual([SETTLE_METERED_DISCRIMINATOR]);
    expect(settleIx.accounts?.map((a) => a.address)).toEqual([
      CHANNEL,
      SYSVAR_INSTRUCTIONS_ADDRESS,
    ]);
  });

  it('rejects a claim passed as the cap', async () => {
    const { cap, claim } = await signedPair();
    expect(() =>
      getSettleMeteredInstructions({ channel: CHANNEL, cap: claim, claim: cap }),
    ).toThrow(RangeError);
  });

  it('rejects a v1 voucher passed as the claim', async () => {
    const { cap, claim } = await signedPair();
    const v1 = new Uint8Array(claim.message);
    v1[1] = 0x01;
    expect(() =>
      getSettleMeteredInstructions({ channel: CHANNEL, cap, claim: { ...claim, message: v1 } }),
    ).toThrow(TypeError);
  });
});

describe('buildSettleMeteredTransaction', () => {
  it('puts pre-instructions before the pair', async () => {
    const { cap, claim } = await signedPair();
    const pre = { programAddress: FEE_PAYER, data: new Uint8Array([9]) };
    const message = buildSettleMeteredTransaction({
      channel: CHANNEL,
      cap,
      claim,
      feePayer: FEE_PAYER,
      lifetime: { blockhash: FEE_PAYER as never, lastValidBlockHeight: 0n },
      preInstructions: [pre],
    });

    expect(message.version).toBe(0);
    expect(message.feePayer.address).toBe(FEE_PAYER);
    expect(message.instructions.map((ix) => ix.programAddress)).toEqual([
      FEE_PAYER,
      ED25519_PROGRAM_ADDRESS,
      ED25519_PROGRAM_ADDRESS,
      PAYMENT_CHANNELS_PROGRAM_ADDRESS,
    ]);
  });
});
