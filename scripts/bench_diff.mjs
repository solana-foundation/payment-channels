#!/usr/bin/env node
// Diff two CU benchmark reports and emit a side-by-side markdown table.
//
// Usage:
//   bench_diff.mjs <bench-base.md> <bench-pr.md>
//
// Reads the markdown tables emitted by `payment_channels`'s bench harness
// (`tests/benchmark/mod.rs::write_report`) and prints a comparison with
// columns: Scenario, CUs (main), CUs (this), Delta, Est Cost (Med) [SOL].

import { readFileSync } from 'node:fs';

/**
 * Parse the bench-harness markdown report.
 * @param {string} path
 * @returns {Map<string, { cus: number, costMed: string }>}
 */
function parseReport(path) {
  const out = new Map();
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line.startsWith('|')) continue;
    const cells = line
      .trim()
      .replace(/^\|/, '')
      .replace(/\|$/, '')
      .split('|')
      .map((c) => c.trim());
    if (cells.length < 5) continue;
    const [scenario, cus, , costMed] = cells;
    // Skip header + separator rows.
    if (scenario === 'Scenario' || scenario === '') continue;
    if (/^[-:]+$/.test(scenario)) continue;
    const cusInt = Number.parseInt(cus, 10);
    if (!Number.isFinite(cusInt)) continue;
    out.set(scenario, { cus: cusInt, costMed });
  }
  return out;
}

/**
 * @param {number} mainCus
 * @param {number} prCus
 */
function formatDelta(mainCus, prCus) {
  const d = prCus - mainCus;
  if (d === 0) return '0';
  const pct = mainCus === 0 ? 0 : (100 * d) / mainCus;
  const sign = d > 0 ? '+' : '';
  return `${sign}${d} (${sign}${pct.toFixed(1)}%)`;
}

function main() {
  const [, , basePath, prPath] = process.argv;
  if (!basePath || !prPath) {
    console.error(`usage: ${process.argv[1]} <base-report> <pr-report>`);
    process.exit(2);
  }

  const base = parseReport(basePath);
  const pr = parseReport(prPath);
  const scenarios = [...new Set([...base.keys(), ...pr.keys()])].sort();

  if (scenarios.length === 0) {
    console.error('no scenarios found in either report');
    process.exit(1);
  }

  const headers = ['Scenario', 'CUs (main)', 'CUs (this)', 'Delta', 'Est Cost (Med) [SOL]'];
  /** @type {("left" | "right")[]} */
  const align = ['left', 'right', 'right', 'right', 'right'];

  /** @type {string[][]} */
  const rows = scenarios.map((s) => {
    const m = base.get(s);
    const p = pr.get(s);
    const cusMain = m ? String(m.cus) : '—';
    const cusPr = p ? String(p.cus) : '—';
    // Prefer the PR's cost estimate; fall back to base when scenario was removed.
    const costMed = (p ?? m).costMed;
    let delta;
    if (m && p) delta = formatDelta(m.cus, p.cus);
    else if (p) delta = '**new**';
    else delta = '_removed_';
    return [s, cusMain, cusPr, delta, costMed];
  });

  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));

  const pad = (cell, i) =>
    align[i] === 'left' ? cell.padEnd(widths[i]) : cell.padStart(widths[i]);
  const fmt = (cells) => `| ${cells.map(pad).join(' | ')} |`;

  console.log(fmt(headers));
  console.log(`|${widths.map((w) => '-'.repeat(w + 2)).join('|')}|`);
  for (const row of rows) console.log(fmt(row));
}

main();
