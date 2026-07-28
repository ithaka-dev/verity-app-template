import assert from 'node:assert/strict';
import {test} from 'node:test';

import {SecretInLogError, _internal, fingerprint} from '../src/logging.ts';

test('fingerprint is deterministic', () => {
  assert.equal(fingerprint('derived-key', 'secret'), fingerprint('derived-key', 'secret'));
});

test('fingerprint is domain-separated', () => {
  // Without this, a value fingerprinted in a harmless context confirms a guess about the same
  // value in a sensitive one.
  assert.notEqual(fingerprint('derived-key', 'secret'), fingerprint('migration-nonce', 'secret'));
});

test('fingerprint does not contain the secret', () => {
  const secret = 'correct-horse-battery-staple';
  assert.ok(!fingerprint('instance-secret', secret).includes(secret));
});

test('fingerprint accepts bytes and strings equivalently', () => {
  assert.equal(
    fingerprint('export-key', 'abc'),
    fingerprint('export-key', new TextEncoder().encode('abc')),
  );
});

test('a PEM private key is refused, not redacted', () => {
  assert.throws(
    () => _internal.assertNoSecret('key: -----BEGIN EC PRIVATE KEY-----\nMHcCAQ'),
    SecretInLogError,
  );
});

test('a field named for a secret is refused', () => {
  assert.throws(() => _internal.assertFieldNameIsSafe('private_key'), SecretInLogError);
  assert.throws(() => _internal.assertFieldNameIsSafe('token'), SecretInLogError);
  assert.throws(() => _internal.assertFieldNameIsSafe('seed'), SecretInLogError);
});

/**
 * A `bytes32` and a private key are the same string shape, so content alone cannot separate them.
 * Refusing every 64-hex value would block compose hashes and instance ids — the values an
 * operational log most needs — and a checker that fires on ordinary data gets removed. The field
 * name carries the distinction instead.
 */
test('a public hash in a public field is allowed', () => {
  assert.doesNotThrow(() => _internal.assertFieldNameIsSafe('compose_hash'));
  assert.doesNotThrow(() => _internal.assertNoSecret(`{"compose_hash":"0x${'a'.repeat(64)}"}`));
});

test('the _fp suffix is the only escape from a suspicious field name', () => {
  assert.doesNotThrow(() => _internal.assertFieldNameIsSafe('key_fp'));
  assert.throws(() => _internal.assertFieldNameIsSafe('key'), SecretInLogError);
});

test('a JWT is refused', () => {
  assert.throws(
    () => _internal.assertNoSecret('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NX0.abc'),
    SecretInLogError,
  );
});

test('ordinary fields still log', () => {
  assert.doesNotThrow(() =>
    _internal.assertNoSecret(JSON.stringify({event: 'migrate_complete', from_schema: 1})),
  );
});

test('a fingerprint is short enough to pass the hex-key check', () => {
  // 16 hex characters, so it cannot trip the 64-character private-key pattern. If the truncation
  // length ever grows to 64 this test fails, which is the point — the safe pattern must not become
  // indistinguishable from the unsafe one.
  assert.doesNotThrow(() =>
    _internal.assertNoSecret(JSON.stringify({key_fp: fingerprint('derived-key', 'k')})),
  );
});
