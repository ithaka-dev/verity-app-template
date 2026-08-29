import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  ComposeCheckError,
  assertReferencesDigest,
  composeHash,
  pinnedImages,
} from '../src/compose-check.ts';

const PINNED = 'sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';

function compose(inner: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({docker_compose_file: inner}));
}

const GOOD = compose(`services:\n  app:\n    image: ghcr.io/x/y@${PINNED}\n`);

test('accepts a digest-pinned image', () => {
  const images = pinnedImages(GOOD);
  assert.equal(images.length, 1);
  assert.equal(images[0]?.service, 'app');
  assert.equal(images[0]?.digest, PINNED);
});

/** The whole reason this module exists. */
test('refuses a tagged image', () => {
  assert.throws(
    () => pinnedImages(compose('services:\n  app:\n    image: ghcr.io/x/y:1.0.0\n')),
    (err: ComposeCheckError) => err.reason === 'not-pinned',
  );
});

test('refuses a bare image with no tag at all', () => {
  assert.throws(
    () => pinnedImages(compose('services:\n  app:\n    image: alpine\n')),
    (err: ComposeCheckError) => err.reason === 'not-pinned',
  );
});

/** A truncated digest is not a weaker pin — it is not a pin. */
test('refuses a malformed or truncated digest', () => {
  for (const bad of ['sha256:abc', 'sha256:' + 'z'.repeat(64), 'md5:' + 'a'.repeat(64)]) {
    assert.throws(
      () => pinnedImages(compose(`services:\n  app:\n    image: ghcr.io/x/y@${bad}\n`)),
      (err: ComposeCheckError) => err.reason === 'not-pinned',
      bad,
    );
  }
});

test('refuses when one of several services is tagged', () => {
  assert.throws(
    () =>
      pinnedImages(
        compose(
          `services:\n  app:\n    image: ghcr.io/x/y@${PINNED}\n  sidecar:\n    image: redis:7\n`,
        ),
      ),
    (err: ComposeCheckError) => err.reason === 'not-pinned',
  );
});

/** A document with nothing to check is not a document that passed the check. */
test('refuses a compose with no images', () => {
  assert.throws(
    () => pinnedImages(compose('services:\n  app:\n    build: .\n')),
    (err: ComposeCheckError) => err.reason === 'no-images',
  );
});

test('refuses input that is not a compose document', () => {
  assert.throws(
    () => pinnedImages(new TextEncoder().encode('not json')),
    (err: ComposeCheckError) => err.reason === 'not-json',
  );
  assert.throws(
    () => pinnedImages(new TextEncoder().encode('{}')),
    (err: ComposeCheckError) => err.reason === 'no-compose-file',
  );
});

test('cross-checks the licensed digest', () => {
  assert.doesNotThrow(() => assertReferencesDigest(GOOD, PINNED));
  assert.doesNotThrow(() => assertReferencesDigest(GOOD, PINNED.replace('sha256:', '')));
  assert.doesNotThrow(() => assertReferencesDigest(GOOD, `0x${PINNED.replace('sha256:', '')}`));
  // Uppercase hex is a form the check accepts, not just a form it happens to tolerate: the compose
  // is pinned lowercase, so this only passes if the comparison is case-insensitive.
  assert.doesNotThrow(() =>
    assertReferencesDigest(GOOD, `sha256:${PINNED.replace('sha256:', '').toUpperCase()}`),
  );
});

test('refuses when the licensed digest is absent from the compose', () => {
  assert.throws(
    () => assertReferencesDigest(GOOD, `sha256:${'11'.repeat(32)}`),
    (err: ComposeCheckError) => err.reason === 'digest-absent',
  );
});

/** sha256, not keccak — the value must match what the platform measures. */
test('composeHash is sha256 of the exact bytes', () => {
  const bytes = new TextEncoder().encode('abc');
  assert.equal(
    composeHash(bytes),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

test('composeHash changes with any byte, including whitespace', () => {
  assert.notEqual(
    composeHash(new TextEncoder().encode('{"a":1}')),
    composeHash(new TextEncoder().encode('{"a": 1}')),
  );
});

/**
 * The template's own compose must pass its own check. A shipped template that fails the rule it
 * teaches is worse than one that teaches nothing.
 */
test('the template compose is itself digest-pinned', () => {
  const bytes = readFileSync(
    fileURLToPath(new URL('../../compose/app-compose.json', import.meta.url)),
  );
  const images = pinnedImages(bytes);
  assert.ok(images.length > 0);
});
