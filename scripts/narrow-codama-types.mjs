#!/usr/bin/env node
// Rewrite `number | bigint` to `bigint` in generated TS files.
// Codama hardcodes the wider union for 64+ bit fields; this script
// tightens it so TS catches `number` at compile time. The flat
// replace is fine because codama only emits that exact substring for
// big-number types. We assert no leftovers after rewriting.

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const generatedRoot = resolve(here, '..', 'clients/typescript/src/generated');

function listTsFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listTsFiles(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

const files = listTsFiles(generatedRoot);
let rewrites = 0;
for (const file of files) {
  const before = readFileSync(file, 'utf8');
  const after = before.replace(/number \| bigint/g, 'bigint');
  if (before !== after) {
    writeFileSync(file, after);
    rewrites += 1;
  }
}

const leftover = files.filter((f) => /number\s*\|\s*bigint/.test(readFileSync(f, 'utf8')));
if (leftover.length > 0) {
  const paths = leftover.map((f) => `  - ${relative(process.cwd(), f)}`).join('\n');
  throw new Error(`narrow-codama-types: lossy unions remain after rewrite:\n${paths}`);
}

console.log(`narrow-codama-types: rewrote ${rewrites} file(s); generated tree is bigint-narrowed.`);
