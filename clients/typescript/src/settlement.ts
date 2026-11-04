// Hand-written helpers for metered settlement (`settleMetered`, and
// `settleAndSeal` with `has_voucher == 2`). The generated client has the
// voucher codecs and the bare instructions; this module adds the signed
// messages, the Ed25519 precompile instructions that carry them, and the
// transaction shape the program expects.

import {
  type Address,
  address,
  appendTransactionMessageInstructions,
  type BlockhashLifetimeConstraint,
  createTransactionMessage,
  getAddressEncoder,
  getAddressFromPublicKey,
  type Instruction,
  pipe,
  type ReadonlyUint8Array,
  type SignatureBytes,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  signBytes,
} from '@solana/kit';
import { getSettleMeteredInstruction } from './generated/instructions/settleMetered.js';
import { getCapVoucherArgsEncoder } from './generated/types/capVoucherArgs.js';
import { getClaimVoucherArgsEncoder } from './generated/types/claimVoucherArgs.js';

/** Magic of a metered cap, signed by `authorizedSigner`. */
export const CAP_VOUCHER_MAGIC = [0x56, 0x03] as const;
/** Magic of a metered claim, signed by the cap's `operator`. */
export const CLAIM_VOUCHER_MAGIC = [0x56, 0x04] as const;

/** Signed-message sizes, taken from the generated codecs. */
export const CAP_VOUCHER_SIZE = getCapVoucherArgsEncoder().fixedSize;
export const CLAIM_VOUCHER_SIZE = getClaimVoucherArgsEncoder().fixedSize;

/** `settleAndSeal.hasVoucher`: seal at the current `settled` watermark. */
export const SETTLE_AND_SEAL_NO_VOUCHER = 0;
/** `settleAndSeal.hasVoucher`: apply the v1 voucher in the preceding Ed25519 ix. */
export const SETTLE_AND_SEAL_V1_VOUCHER = 1;
/** `settleAndSeal.hasVoucher`: apply the cap/claim pair in the two preceding Ed25519 ixs. */
export const SETTLE_AND_SEAL_METERED_VOUCHER = 2;

export const ED25519_PROGRAM_ADDRESS = address('Ed25519SigVerify111111111111111111111111111');
export const SYSVAR_INSTRUCTIONS_ADDRESS = address('Sysvar1nstructions1111111111111111111111111');

// Canonical single-signature inline layout pinned by the program's parser:
// `[num_signatures = 1, padding = 0, offsets(14), pubkey(32), signature(64), message]`.
const PUBKEY_OFFSET = 16;
const SIGNATURE_OFFSET = 48;
const MESSAGE_OFFSET = 112;
const CURRENT_INSTRUCTION = 0xffff;

export type CapVoucherInput = {
  channelId: Address;
  /** Ceiling on the claim; must not exceed the channel deposit. */
  capCumulative: bigint;
  /** Unix seconds; `0n` (the default) means no expiry. */
  expiresAt?: bigint;
  /** Key allowed to sign claims under this cap. */
  operator: Address;
};

export type ClaimVoucherInput = {
  channelId: Address;
  /** New `settled` watermark; must be above `settled` and at most the cap. */
  claimCumulative: bigint;
  /** Unix seconds; `0n` (the default) means no expiry. */
  expiresAt?: bigint;
};

/** A voucher message with the Ed25519 signature over it. */
export type SignedVoucherMessage = {
  message: ReadonlyUint8Array;
  signer: Address;
  signature: SignatureBytes;
};

/** The 82 bytes the client signs to authorize claims up to `capCumulative`. */
export function encodeCapVoucher(input: CapVoucherInput): ReadonlyUint8Array {
  return getCapVoucherArgsEncoder().encode({
    magic: [...CAP_VOUCHER_MAGIC],
    channelId: input.channelId,
    capCumulative: input.capCumulative,
    expiresAt: input.expiresAt ?? 0n,
    operator: input.operator,
  });
}

/** The 50 bytes the operator signs to charge `claimCumulative`. */
export function encodeClaimVoucher(input: ClaimVoucherInput): ReadonlyUint8Array {
  return getClaimVoucherArgsEncoder().encode({
    magic: [...CLAIM_VOUCHER_MAGIC],
    channelId: input.channelId,
    claimCumulative: input.claimCumulative,
    expiresAt: input.expiresAt ?? 0n,
  });
}

/** Sign a voucher message with an Ed25519 key pair. */
export async function signVoucherMessage(
  keyPair: { privateKey: CryptoKey; publicKey: CryptoKey },
  message: ReadonlyUint8Array,
): Promise<SignedVoucherMessage> {
  const [signer, signature] = await Promise.all([
    getAddressFromPublicKey(keyPair.publicKey),
    signBytes(keyPair.privateKey, message),
  ]);
  return { message, signer, signature };
}

/**
 * Ed25519 precompile instruction in the only layout the program accepts:
 * one signature, pubkey/signature/message inline at the canonical offsets,
 * and every instruction index set to "this instruction".
 */
export function getEd25519VerifyInstruction(signed: SignedVoucherMessage): Instruction {
  const { message, signature } = signed;
  if (signature.length !== 64) {
    throw new RangeError(`Ed25519 signature must be 64 bytes, got ${signature.length}`);
  }
  const data = new Uint8Array(MESSAGE_OFFSET + message.length);
  const view = new DataView(data.buffer);
  data[0] = 1;
  data[1] = 0;
  const offsets = [
    SIGNATURE_OFFSET,
    CURRENT_INSTRUCTION,
    PUBKEY_OFFSET,
    CURRENT_INSTRUCTION,
    MESSAGE_OFFSET,
    message.length,
    CURRENT_INSTRUCTION,
  ];
  offsets.forEach((value, i) => view.setUint16(2 + i * 2, value, true));
  data.set(getAddressEncoder().encode(signed.signer), PUBKEY_OFFSET);
  data.set(signature, SIGNATURE_OFFSET);
  data.set(message, MESSAGE_OFFSET);
  return { programAddress: ED25519_PROGRAM_ADDRESS, data };
}

export type MeteredSettlementInput = {
  channel: Address;
  /** Cap signed by the channel's `authorizedSigner`. */
  cap: SignedVoucherMessage;
  /** Claim signed by the cap's `operator`. */
  claim: SignedVoucherMessage;
};

/**
 * `[ed25519(cap), ed25519(claim), settleMetered]`, in that order. Nothing may
 * sit between the pair and `settleMetered`; put compute-budget instructions
 * before the pair.
 */
export function getSettleMeteredInstructions(input: MeteredSettlementInput): Instruction[] {
  assertMessage('cap', input.cap.message, CAP_VOUCHER_SIZE, CAP_VOUCHER_MAGIC);
  assertMessage('claim', input.claim.message, CLAIM_VOUCHER_SIZE, CLAIM_VOUCHER_MAGIC);
  return [
    getEd25519VerifyInstruction(input.cap),
    getEd25519VerifyInstruction(input.claim),
    getSettleMeteredInstruction({
      channel: input.channel,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_ADDRESS,
    }),
  ];
}

export type BuildSettleMeteredTransactionInput = MeteredSettlementInput & {
  feePayer: Address;
  lifetime: BlockhashLifetimeConstraint;
  /** Placed before the pair, e.g. compute-budget instructions. */
  preInstructions?: Instruction[];
};

/** Version 0 transaction message for a metered settlement, ready to sign. */
export function buildSettleMeteredTransaction(input: BuildSettleMeteredTransactionInput) {
  return pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayer(input.feePayer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(input.lifetime, m),
    (m) =>
      appendTransactionMessageInstructions(
        [...(input.preInstructions ?? []), ...getSettleMeteredInstructions(input)],
        m,
      ),
  );
}

function assertMessage(
  label: string,
  message: ReadonlyUint8Array,
  size: number,
  magic: readonly [number, number],
): void {
  if (message.length !== size) {
    throw new RangeError(`${label} message must be ${size} bytes, got ${message.length}`);
  }
  if (message[0] !== magic[0] || message[1] !== magic[1]) {
    throw new TypeError(`${label} message has the wrong magic`);
  }
}
