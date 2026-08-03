#!/usr/bin/env node
/**
 * Assert every source module appears in the coverage report.
 *
 * ## Why this exists
 *
 * Node's coverage only reports files it *loaded*. A module no test imports is therefore **absent
 * from the report**, not shown at 0% — so a summary reading "97.5% all files" was omitting an
 * entire module, and looked healthier than a report that had honestly shown it red.
 *
 * That is how `eip3009.ts` — the settlement path invariant I4 rests on — sat completely untested
 * behind a number nobody had reason to question. Percentages cannot catch this, because the missing
 * file is missing from the denominator too.
 *
 * So this checks *presence*, which is the one thing a coverage percentage structurally cannot.
 *
 * Usage:
 *   node --test --experimental-test-coverage … 2>&1 | node script/check-coverage-completeness.mjs src
 */

import {readdirSync, statSync} from 'node:fs';
import {join, relative} from 'node:path';

const srcDir = process.argv[2] ?? 'src';

/** Every `.ts` under `src`, excluding type-only barrels which legitimately emit nothing. */
function sourceModules(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      out.push(...sourceModules(path));
    } else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) {
      out.push(relative(srcDir, path));
    }
  }
  return out;
}

const report = await new Promise((resolve) => {
  let text = '';
  process.stdin.on('data', (chunk) => (text += chunk));
  process.stdin.on('end', () => resolve(text));
});

const expected = sourceModules(srcDir);
// The report indents nested paths, so match on the basename — enough to tell present from absent,
// and immune to how the tool chooses to render a tree.
const missing = expected.filter((module) => {
  const base = module.split('/').pop();
  return !report.includes(base);
});

if (missing.length > 0) {
  console.error('::error::these source modules never appear in the coverage report:');
  for (const module of missing) console.error(`  ${srcDir}/${module}`);
  console.error(
    '\nA module no test imports is absent from the report rather than shown at 0%, so the ' +
      'percentage above it is computed without it and reads as clean. Import it from a test — ' +
      'even a trivial one — so its real coverage becomes visible.',
  );
  process.exit(1);
}

console.log(`ok: all ${expected.length} source modules appear in the coverage report`);
