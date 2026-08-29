/**
 * Publish-time CLI over `compose-check.ts`.
 *
 * Thin means thin: this file parses arguments, reads bytes, calls the library, and renders the
 * outcome. Every checking rule — what counts as pinned, what reasons exist, what the prose for
 * each one says — lives in `compose-check.ts` and is reused verbatim here.
 */

import {readFileSync} from 'node:fs';

import {
  ComposeCheckError,
  assertReferencesDigest,
  composeHash,
  normaliseImageDigest,
  pinnedImages,
} from './compose-check.ts';

/**
 * Exit codes are the CLI's contract with L-05 and with every copied publish pipeline.
 *
 * The line between 1 and 2 is "did the CLI hold the document in its hands?" `ok` means every check
 * that was asked for ran and passed; `refused` means the CLI read the document and judged it
 * unpublishable — that includes `not-json` and `no-compose-file`, because a document we opened and
 * could not make sense of is still a judgement about *that* document, not a failure to obtain one;
 * `unusable` is reserved for never getting as far as looking at bytes at all (bad arguments, a
 * missing or unreadable file). Getting this backwards teaches every copied pipeline the wrong
 * distinction between "your compose is unsafe" and "I could not read the file".
 */
export const EXIT = {ok: 0, refused: 1, unusable: 2} as const;
export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/** Output sinks, injected so `main` is testable in-process and never touches `process`. */
export interface CheckComposeIo {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

const USAGE = 'check-compose: usage: check-compose <compose.json> [licensed-image-digest]';

/**
 * Parse arguments, read bytes, call the library, render the outcome.
 *
 * Returns an exit code; never calls `process.exit`, never throws.
 */
export function main(argv: readonly string[], io: CheckComposeIo): ExitCode {
  // Destructuring once yields every branch live: `path === undefined` fires exactly when zero
  // arguments were given, and `rest.length > 0` exactly when more than two were. Neither guard is
  // dead code — a length check followed by re-indexing `argv[0]` would add a second, unreachable
  // undefined test under `noUncheckedIndexedAccess`.
  const [path, licensedDigest, ...rest] = argv;
  if (path === undefined || rest.length > 0) {
    io.err(USAGE);
    return EXIT.unusable;
  }

  let bytes: Buffer;
  try {
    bytes = readFileSync(path); // a Buffer, which *is* a Uint8Array — no decode/re-encode round trip
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    io.err(`check-compose: cannot read ${path}: ${message}`);
    return EXIT.unusable;
  }

  try {
    const images = pinnedImages(bytes);
    if (licensedDigest !== undefined) {
      assertReferencesDigest(bytes, licensedDigest);
    }

    const count = images.length;
    io.out(`check-compose: ok — ${count} image${count === 1 ? '' : 's'}, all digest-pinned`);
    for (const image of images) io.out(`  ${image.service}  ${image.reference}`);
    io.out(`  composeHash of these bytes: ${composeHash(bytes)}`);
    if (licensedDigest !== undefined) {
      io.out(
        `  cross-checked: the compose references the licensed digest ${normaliseImageDigest(licensedDigest)}`,
      );
    } else {
      io.out(
        '  note: no licensed image digest was given, so the compose was NOT checked against a ' +
          'version record. Pass it as a second argument to check that too.',
      );
    }
    return EXIT.ok;
  } catch (err: unknown) {
    if (err instanceof ComposeCheckError) {
      io.err(`check-compose: ${err.reason}: ${err.message}`);
      return EXIT.refused;
    }
    // Not a judgement about the document — something else went wrong. Visible, not swallowed.
    const message = err instanceof Error ? err.message : String(err);
    io.err(`check-compose: unexpected error: ${message}`);
    return EXIT.unusable;
  }
}
