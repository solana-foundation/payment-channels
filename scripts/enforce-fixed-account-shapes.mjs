#!/usr/bin/env node
// Align generated clients with the on-chain fixed account shapes.
//
// Every instruction whose committed-IDL entry lacks `remainingAccounts` takes
// an exact account list on chain and rejects extras, but codama's renderers
// emit permissive parsers (`accounts.length < N`) and remaining-accounts
// builder APIs for every instruction. This script flips the TS parser guards
// to `!== N` and strips the remaining-accounts API from the Rust builders for
// those fixed-shape instructions. Counts are asserted exactly, so a codama
// upgrade that reshapes its templates breaks `pnpm run generate` instead of
// shipping permissive clients again. The classification itself is checked by
// the dynamic_tail_handlers_match_idl_remaining_accounts test in
// program/payment_channels/tests/codama_visitor_idl.rs.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
const IDL_PATH = join(repoRoot, 'program/payment_channels/idl/payment_channels.json');
const TS_DIR = join(repoRoot, 'clients/typescript/src/generated/instructions');
const RUST_DIR = join(repoRoot, 'clients/rust/src/generated/instructions');

const idl = JSON.parse(readFileSync(IDL_PATH, 'utf8'));
const instructions = idl?.program?.instructions;
if (!Array.isArray(instructions) || instructions.length === 0) {
  throw new Error('enforce-fixed-account-shapes: committed IDL has no instructions');
}

const hasTail = (ix) => Array.isArray(ix.remainingAccounts) && ix.remainingAccounts.length > 0;
const fixedShape = instructions.filter((ix) => !hasTail(ix));
const tailNames = instructions.filter(hasTail).map((ix) => ix.name);
if (!tailNames.includes('distribute')) {
  throw new Error('enforce-fixed-account-shapes: expected distribute to declare remainingAccounts');
}

const camelToSnake = (s) => s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

// --- TypeScript: parser guard `< N` -> `!== N` ------------------------------

for (const ix of fixedShape) {
  const file = join(TS_DIR, `${ix.name}.ts`);
  const expected = ix.accounts.length;
  const before = readFileSync(file, 'utf8');
  const pattern = `if (instruction.accounts.length < ${expected}) {`;
  const occurrences = before.split(pattern).length - 1;
  if (occurrences !== 1) {
    throw new Error(
      `enforce-fixed-account-shapes: ${ix.name}.ts: expected exactly 1 occurrence of \`${pattern}\`, found ${occurrences}`,
    );
  }
  writeFileSync(
    file,
    before.replace(pattern, `if (instruction.accounts.length !== ${expected}) {`),
  );
}

// --- Rust: remove the remaining-accounts API from fixed-shape builders ------

// `pub fn name(` -> `fn name(`, asserting exactly one occurrence (call sites
// don't carry the `pub fn ` prefix, so they never match).
function demote(source, file, fnName) {
  const pattern = `pub fn ${fnName}(`;
  const occurrences = source.split(pattern).length - 1;
  if (occurrences !== 1) {
    throw new Error(
      `enforce-fixed-account-shapes: ${file}: expected exactly 1 \`${pattern}\`, found ${occurrences}`,
    );
  }
  return source.replace(pattern, `fn ${fnName}(`);
}

// The deleted method blocks are byte-identical across every generated
// instruction file (their bodies only touch `__remaining_accounts`), so each
// is matched and removed as an exact string. A codama template change makes
// the occurrence count fail loudly instead of leaving stragglers behind.
const BUILDER_REMAINING_API = `    /// Add an additional account to the instruction.
    #[inline(always)]
    pub fn add_remaining_account(&mut self, account: solana_instruction::AccountMeta) -> &mut Self {
        self.__remaining_accounts.push(account);
        self
    }
    /// Add additional accounts to the instruction.
    #[inline(always)]
    pub fn add_remaining_accounts(
        &mut self,
        accounts: &[solana_instruction::AccountMeta],
    ) -> &mut Self {
        self.__remaining_accounts.extend_from_slice(accounts);
        self
    }
`;

const INVOKE_WITH_REMAINING_ACCOUNTS = `    #[inline(always)]
    pub fn invoke_with_remaining_accounts(
        &self,
        remaining_accounts: &[(&'b solana_account_info::AccountInfo<'a>, bool, bool)],
    ) -> solana_program_error::ProgramResult {
        self.invoke_signed_with_remaining_accounts(&[], remaining_accounts)
    }
`;

const CPI_BUILDER_REMAINING_API = `    /// Add an additional account to the instruction.
    #[inline(always)]
    pub fn add_remaining_account(
        &mut self,
        account: &'b solana_account_info::AccountInfo<'a>,
        is_writable: bool,
        is_signer: bool,
    ) -> &mut Self {
        self.instruction
            .__remaining_accounts
            .push((account, is_writable, is_signer));
        self
    }
    /// Add additional accounts to the instruction.
    ///
    /// Each account is represented by a tuple of the \`AccountInfo\`, a \`bool\` indicating whether the account is writable or not,
    /// and a \`bool\` indicating whether the account is a signer or not.
    #[inline(always)]
    pub fn add_remaining_accounts(
        &mut self,
        accounts: &[(&'b solana_account_info::AccountInfo<'a>, bool, bool)],
    ) -> &mut Self {
        self.instruction
            .__remaining_accounts
            .extend_from_slice(accounts);
        self
    }
`;

function removeBlock(source, file, label, block) {
  const occurrences = source.split(block).length - 1;
  if (occurrences !== 1) {
    throw new Error(
      `enforce-fixed-account-shapes: ${file}: expected exactly 1 ${label} block, found ${occurrences}`,
    );
  }
  return source.replace(block, '');
}

for (const ix of fixedShape) {
  const file = `${camelToSnake(ix.name)}.rs`;
  const path = join(RUST_DIR, file);
  let source = readFileSync(path, 'utf8');

  source = demote(source, file, 'instruction_with_remaining_accounts');
  source = demote(source, file, 'invoke_signed_with_remaining_accounts');
  // No internal callers (invoke/invoke_signed delegate straight to the
  // signed variant), so this one is deleted rather than left as dead code.
  source = removeBlock(
    source,
    file,
    'invoke_with_remaining_accounts',
    INVOKE_WITH_REMAINING_ACCOUNTS,
  );
  source = removeBlock(source, file, 'builder remaining-accounts', BUILDER_REMAINING_API);
  source = removeBlock(source, file, 'CPI-builder remaining-accounts', CPI_BUILDER_REMAINING_API);

  if (/pub fn \w*remaining/.test(source) || source.includes('add_remaining_account')) {
    throw new Error(
      `enforce-fixed-account-shapes: ${file}: remaining-accounts API survived the rewrite`,
    );
  }
  writeFileSync(path, source);
}

console.log(
  `enforce-fixed-account-shapes: tightened ${fixedShape.length} fixed-shape instruction(s), ` +
    `tail instruction(s) untouched: ${tailNames.join(', ')}.`,
);
