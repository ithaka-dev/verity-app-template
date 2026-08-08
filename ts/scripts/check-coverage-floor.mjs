#!/usr/bin/env node
/**
 * Fail the build when coverage drops below the recorded floors.
 *
 * ## Why this exists as a script
 *
 * Rust has `cargo llvm-cov --fail-under-lines`, Python has `pytest --cov-fail-under`, Foundry's
 * numbers are checked by `script/check-coverage.py` next door. Node's test runner reports coverage
 * and offers no way to fail on it, so the gate has to be written.
 *
 * ## What it is not
 *
 * It is **not** the same check as `check-coverage-completeness.mjs`, and neither replaces the other.
 * This one asks whether the number slipped. That one asks whether a module is in the report at all —
 * which a percentage structurally cannot, because a module no test imports is *absent* rather than
 * shown at 0%, so the percentage above it is computed without it and reads as clean. That is exactly
 * how `config.ts` and `guest-agent.ts` sat completely untested behind a 98% — and `guest-agent.ts`
 * encodes the fact that dStack's agent is on `tappd.sock`, established by experiment and copied into
 * every app built from this template.
 *
 * A floor over a number that omits a file is a floor over the wrong number. Run both.
 *
 * ## On the floors themselves
 *
 * Set just below current, so a regression trips them rather than an honest commit having to argue
 * with the gate. **Raise them as coverage improves; never lower one to make a build pass.** If a
 * change genuinely justifies a lower floor, that belongs in the commit message where a reviewer
 * sees it — not in a quiet edit to this file.
 *
 * Usage:
 *   node --test --experimental-test-coverage … 2>&1 | node scripts/check-coverage-floor.mjs
 */

const FLOORS = {line: 97, branch: 93, function: 95};

const report = await new Promise((resolve) => {
  let buffer = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buffer += chunk;
  });
  process.stdin.on('end', () => resolve(buffer));
});

// The summary row Node emits. The line prefix is **version-dependent** — Node 24 writes `ℹ`, Node
// 22 writes `#` — so this matches the row itself rather than trying to enumerate prefixes. CI runs
// Node 22 and found this the hard way: the gate saw no summary and refused, which is the right
// direction to fail but for the wrong reason.
const summary = report.split('\n').find((line) => /\ball files\s*\|/u.test(line));

if (!summary) {
  // A missing summary must fail. If this returned success the gate would pass hardest at exactly
  // the moment the test run died before reporting anything.
  console.error('::error::no coverage summary found — did the test run produce one?');
  console.error(report.slice(-2000));
  process.exit(1);
}

const numbers = summary.match(/\d+\.\d+/gu)?.map(Number) ?? [];
if (numbers.length < 3) {
  console.error(`::error::expected three percentages in the summary, parsed ${numbers}`);
  console.error(summary);
  process.exit(1);
}

const [line, branch, fn] = numbers;
const actual = {line, branch, function: fn};

const below = Object.entries(FLOORS)
  .filter(([metric, floor]) => actual[metric] < floor)
  .map(([metric, floor]) => `${metric} ${actual[metric].toFixed(2)}% < ${floor.toFixed(2)}%`);

if (below.length > 0) {
  console.error(`::error::coverage below threshold — ${below.join('; ')}`);
  process.exit(1);
}

const report_line = Object.entries(actual)
  .map(([metric, value]) => `${metric} ${value.toFixed(2)}%`)
  .join(', ');
console.log(`ok: ${report_line}`);
