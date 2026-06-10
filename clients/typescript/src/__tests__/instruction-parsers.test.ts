import {
  AccountRole,
  createNoopSigner,
  getAddressDecoder,
  isSolanaError,
  SOLANA_ERROR__PROGRAM_CLIENTS__INSUFFICIENT_ACCOUNT_METAS,
  type AccountMeta,
  type Address,
} from '@solana/kit';
import { describe, expect, it } from 'vitest';
import {
  getDistributeInstructionDataEncoder,
  getRequestCloseInstruction,
  PAYMENT_CHANNELS_PROGRAM_ADDRESS,
  parseDistributeInstruction,
  parseRequestCloseInstruction,
} from '../generated/index.js';

// Any valid base58 address works; system program is the easiest to grab.
const SYSTEM_ADDR = '11111111111111111111111111111111' as Address;
const EXTRA_META: AccountMeta = { address: SYSTEM_ADDR, role: AccountRole.READONLY };

describe('fixed-shape parsers mirror the on-chain exact account lists', () => {
  const exact = getRequestCloseInstruction({
    payer: createNoopSigner(SYSTEM_ADDR),
    channel: SYSTEM_ADDR,
  });

  it('parses a builder-produced requestClose instruction (exactly 2 accounts)', () => {
    const parsed = parseRequestCloseInstruction(exact);
    expect(parsed.accounts.payer.address).toBe(SYSTEM_ADDR);
    expect(parsed.accounts.channel.address).toBe(SYSTEM_ADDR);
  });

  it('rejects a requestClose instruction with one extra account', () => {
    const oversupplied = { ...exact, accounts: [...exact.accounts, EXTRA_META] };
    let thrown: unknown;
    try {
      parseRequestCloseInstruction(oversupplied);
    } catch (error) {
      thrown = error;
    }
    // The kit has no wrong-account-count error, so the parser reuses the
    // insufficient-metas one for the too-many direction as well.
    expect(isSolanaError(thrown, SOLANA_ERROR__PROGRAM_CLIENTS__INSUFFICIENT_ACCOUNT_METAS)).toBe(
      true,
    );
  });

  it('still parses distribute with a remaining-accounts tail (10 fixed + 2 extra)', () => {
    // Distinct address per slot so the assertion pins positional mapping.
    const metas: AccountMeta[] = Array.from({ length: 12 }, (_, i) => ({
      address: getAddressDecoder().decode(new Uint8Array(32).fill(i + 1)),
      role: AccountRole.READONLY,
    }));
    const distribute = {
      programAddress: PAYMENT_CHANNELS_PROGRAM_ADDRESS,
      accounts: metas,
      data: getDistributeInstructionDataEncoder().encode({
        distributeArgs: { recipients: [] },
      }),
    };
    const parsed = parseDistributeInstruction(distribute);
    const named = [
      parsed.accounts.channel,
      parsed.accounts.payer,
      parsed.accounts.channelTokenAccount,
      parsed.accounts.payerTokenAccount,
      parsed.accounts.payeeTokenAccount,
      parsed.accounts.treasuryTokenAccount,
      parsed.accounts.mint,
      parsed.accounts.tokenProgram,
      parsed.accounts.eventAuthority,
      parsed.accounts.selfProgram,
    ];
    expect(named.map((meta) => meta.address)).toEqual(
      metas.slice(0, 10).map((meta) => meta.address),
    );
  });
});
