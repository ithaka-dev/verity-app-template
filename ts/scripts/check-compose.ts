/**
 * `check-compose` — the CLI L-05 invokes. No branches live here; see `compose-check-cli.ts`.
 *
 *     node --experimental-strip-types ts/scripts/check-compose.ts <compose.json> [licensed-image-digest]
 */

import {main} from '../src/compose-check-cli.ts';

process.exitCode = main(process.argv.slice(2), {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
});
