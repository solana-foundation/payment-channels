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
if (fixedShape.length !== instructions.length - tailNames.length) {
  throw new Error('enforce-fixed-account-shapes: classification mismatch');
}

const camelToSnake = (s) => s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

// Tail instructions must come out of this script byte-identical. Snapshot
// them up front and verify at the end, since structural exclusion alone would
// not catch a future bug that touches the wrong file.
const tailSnapshots = tailNames.flatMap((name) => {
  const paths = [join(TS_DIR, `${name}.ts`), join(RUST_DIR, `${camelToSnake(name)}.rs`)];
  return paths.map((path) => [path, readFileSync(path, 'utf8')]);
});

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

// Deletes every `pub fn <fnName>(...) { ... }` block, including its
// contiguous preceding doc comments and attributes. Brace-balanced (the
// method bodies vary between one-liners and multi-line blocks).
const DOC_OR_ATTR = /^\s*(\/\/\/|#\[)/;
function removeMethodBlocks(source, fnName) {
  const lines = source.split('\n');
  let removed = 0;
  for (let i = 0; i < lines.length; i += 1) {
    if (!lines[i].includes(`pub fn ${fnName}(`)) continue;
    let start = i;
    while (start > 0 && DOC_OR_ATTR.test(lines[start - 1])) start -= 1;
    let depth = 0;
    let opened = false;
    let end = -1;
    for (let j = i; j < lines.length; j += 1) {
      for (const ch of lines[j]) {
        if (ch === '{') {
          depth += 1;
          opened = true;
        } else if (ch === '}') {
          depth -= 1;
        }
      }
      if (opened && depth === 0) {
        end = j;
        break;
      }
    }
    if (end === -1) {
      throw new Error(`enforce-fixed-account-shapes: could not find the body of \`${fnName}\``);
    }
    lines.splice(start, end - start + 1);
    removed += 1;
    i = start - 1;
  }
  return [lines.join('\n'), removed];
}

function removeExactly(source, file, fnName, expected) {
  const [out, removed] = removeMethodBlocks(source, fnName);
  if (removed !== expected) {
    throw new Error(
      `enforce-fixed-account-shapes: ${file}: expected to delete ${expected} \`${fnName}\` block(s), deleted ${removed}`,
    );
  }
  return out;
}

for (const ix of fixedShape) {
  const file = `${camelToSnake(ix.name)}.rs`;
  const path = join(RUST_DIR, file);
  let source = readFileSync(path, 'utf8');

  source = demote(source, file, 'instruction_with_remaining_accounts');
  source = demote(source, file, 'invoke_signed_with_remaining_accounts');
  // No internal callers (invoke/invoke_signed delegate straight to the
  // signed variant), so this one is deleted rather than left as dead code.
  source = removeExactly(source, file, 'invoke_with_remaining_accounts', 1);
  source = removeExactly(source, file, 'add_remaining_account', 2);
  source = removeExactly(source, file, 'add_remaining_accounts', 2);

  if (/pub fn \w*remaining/.test(source) || source.includes('add_remaining_account')) {
    throw new Error(
      `enforce-fixed-account-shapes: ${file}: remaining-accounts API survived the rewrite`,
    );
  }
  writeFileSync(path, source);
}

for (const [path, before] of tailSnapshots) {
  if (readFileSync(path, 'utf8') !== before) {
    throw new Error(`enforce-fixed-account-shapes: tail instruction file was modified: ${path}`);
  }
}

console.log(
  `enforce-fixed-account-shapes: tightened ${fixedShape.length} fixed-shape instruction(s), ` +
    `tail instruction(s) untouched: ${tailNames.join(', ')}.`,
);
