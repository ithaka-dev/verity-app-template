/**
 * Regressions from the adversarial review.
 *
 * Every test here is a defect that shipped. They are kept together, and each names the failure, so
 * the next person reads the reasoning rather than rediscovering it.
 */

import assert from 'node:assert/strict';
import {mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';

import type {Hex, PublicClient} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';

import {
  EXPORT_AUTHORIZATION_TYPES,
  MAX_AUTHORIZATION_LIFETIME_SECONDS,
  MIGRATION_AUTHORIZATION_TYPES,
  migrationDomain,
  type ExportAuthorization,
  type MigrationAuthorization,
} from '../src/authorization.ts';
import type {AppConfig} from '../src/config.ts';
import {exportState} from '../src/handlers/export.ts';
import {migrate, toBytes32} from '../src/handlers/migrate.ts';
import type {GuestAgent} from '../src/guest-agent.ts';
import {SecretInLogError, _internal, fingerprint, log} from '../src/logging.ts';
import {generateRecipientKeypair, open, parseRecipientKey} from '../src/seal.ts';
import {PROFILES_DOCUMENT} from '../src/state/migrations.ts';
import {JsonStore} from '../src/state/store.ts';

const HOLDER = privateKeyToAccount(`0x${'11'.repeat(32)}`);

/** Realistic: dStack reports a bare 20-byte hex id with no `0x`. */
const RAW_INSTANCE_ID = 'e3f2a1b0c9d8e7f60514233241506978a9bacbdc';
const RUNNING_COMPOSE = `0x${'ab'.repeat(32)}` as Hex;

const CONFIG: AppConfig = {
  chainId: 84532,
  rpcUrl: 'https://example.invalid',
  licenseToken: '0x1111111111111111111111111111111111111111',
  appManifest: '0x2222222222222222222222222222222222222222',
  version: '1.0.0',
  publicLogs: true,
};

function guestAgent(): GuestAgent {
  return {
    info: async () => ({appId: '0xapp', instanceId: RAW_INSTANCE_ID, composeHash: RUNNING_COMPOSE}),
  } as unknown as GuestAgent;
}

function client(): PublicClient {
  return {getCode: async () => undefined, readContract: async () => 1n} as unknown as PublicClient;
}

// — H4: the denylist matched only snake_case, i.e. almost nothing in a camelCase codebase —

test('camelCase secret field names are refused', () => {
  for (const field of [
    'privateKey',
    'derivedKey',
    'apiKey',
    'signingKey',
    'sessionToken',
    'x25519PrivateKey',
    'password',
    'secretValue',
    'api-key',
    'privkey',
  ]) {
    assert.throws(() => _internal.assertFieldNameIsSafe(field), SecretInLogError, field);
  }
});

test('ordinary field names still pass', () => {
  for (const field of ['compose_hash', 'instanceId', 'schemaVersion', 'fromSchema', 'key_fp']) {
    assert.doesNotThrow(() => _internal.assertFieldNameIsSafe(field), field);
  }
});

/** The `_fp` escape was granted on the name alone, so `{key_fp: rawPrivateKey}` passed unchecked. */
test('a _fp field must actually carry a fingerprint', () => {
  assert.throws(() => log('x', {key_fp: 'a'.repeat(64)}), SecretInLogError);
  assert.doesNotThrow(() => log('x', {key_fp: fingerprint('derived-key', 'k')}));
});

/** A log line whose name is caller-chosen hides from every filter looking for it. */
test('a caller-supplied field cannot rename the event', () => {
  const lines: string[] = [];
  const original = console.log;
  console.log = (line: string) => lines.push(line);
  try {
    log('boot', {event: 'hijacked'} as never);
  } finally {
    console.log = original;
  }
  assert.equal(JSON.parse(lines[0]!).event, 'boot');
});

/** The type said the domains were a closed set; the runtime did not. */
test('an unknown fingerprint domain is refused at runtime', () => {
  assert.throws(() => fingerprint('derived-key|x' as never, 'y'), TypeError);
});

// — H2: an unbounded expiry turns one holder act into a standing permission —

test('an authorization with an over-long lifetime is refused', async () => {
  const store = new JsonStore(await mkdtemp(join(tmpdir(), 'verity-clamp-')));
  const authorization: MigrationAuthorization = {
    licenseId: 1n,
    fromDigest: `0x${'cd'.repeat(32)}`,
    toDigest: RUNNING_COMPOSE,
    instanceId: toBytes32(RAW_INSTANCE_ID),
    nonce: 1n,
    expiry: 1_000n + MAX_AUTHORIZATION_LIFETIME_SECONDS + 1n,
  };
  const signature = await HOLDER.signTypedData({
    domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
    types: MIGRATION_AUTHORIZATION_TYPES,
    primaryType: 'MigrationAuthorization',
    message: authorization,
  });

  const result = await migrate(
    {authorization, signature, signer: HOLDER.address},
    {config: CONFIG, client: client(), guestAgent: guestAgent(), store, now: () => 1_000n},
  );
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /window this long/);
});

// — H2: one signature authorizes one export, not continuing access —

async function exportOnce(store: JsonStore, recipientHex: string, nonce: bigint) {
  const authorization: ExportAuthorization = {
    licenseId: 1n,
    instanceId: toBytes32(RAW_INSTANCE_ID),
    recipientPublicKey: `0x${recipientHex}` as Hex,
    nonce,
    expiry: 1_600n,
  };
  const signature = await HOLDER.signTypedData({
    domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
    types: EXPORT_AUTHORIZATION_TYPES,
    primaryType: 'ExportAuthorization',
    message: authorization,
  });
  return exportState(
    {authorization, signature, signer: HOLDER.address},
    {config: CONFIG, client: client(), guestAgent: guestAgent(), store, now: () => 1_000n},
  );
}

test('an export authorization cannot be replayed', async () => {
  const store = new JsonStore(await mkdtemp(join(tmpdir(), 'verity-replay-')));
  await store.write(PROFILES_DOCUMENT, {schemaVersion: 2, data: {profiles: []}});
  const {publicKeyHex} = generateRecipientKeypair();

  const first = await exportOnce(store, publicKeyHex, 7n);
  assert.equal(first.status, 'complete');

  // The replay would return whatever the state is *now*, not a cached copy — a standing tap held
  // by the orchestrator, which §2.8 says must become untrusted.
  const second = await exportOnce(store, publicKeyHex, 7n);
  assert.equal(second.status, 'failed');
  assert.match(second.detail, /already been used/);
  assert.equal(second.bundle, undefined);
});

// — H5: the bundle must open using the instance id the holder signed —

test('the holder can open a bundle using the signed instance id', async () => {
  const store = new JsonStore(await mkdtemp(join(tmpdir(), 'verity-seal-')));
  await store.write(PROFILES_DOCUMENT, {
    schemaVersion: 2,
    data: {profiles: [{id: 'a', givenName: 'Ada', familyName: 'Lovelace'}]},
  });
  const {publicKeyHex, privateKey} = generateRecipientKeypair();

  const result = await exportOnce(store, publicKeyHex, 1n);
  assert.equal(result.status, 'complete');
  assert.ok(result.bundle);

  // The holder has the signed authorization and nothing else — this is the only instance id they
  // possess. Sealing against the raw guest-agent string made the bundle unopenable, which the
  // holder would have discovered when they needed the data.
  const plaintext = open(result.bundle, privateKey, {
    licenseId: 1n,
    instanceId: toBytes32(RAW_INSTANCE_ID),
  });
  assert.match(plaintext.toString('utf8'), /Lovelace/);
});

test('a small-order recipient key is refused', () => {
  for (const point of ['00'.repeat(32), `01${'00'.repeat(31)}`]) {
    assert.throws(() => parseRecipientKey(point), /small-order|not a valid/);
  }
});

// — H3: the journal must key on the whole authorization, not a holder-chosen nonce —

test('a different authorization reusing a nonce is not skipped', async () => {
  const store = new JsonStore(await mkdtemp(join(tmpdir(), 'verity-journal-')));
  await store.write(PROFILES_DOCUMENT, {
    schemaVersion: 1,
    data: {profiles: [{id: 'a', name: 'Ada Lovelace'}]},
  });

  const base: MigrationAuthorization = {
    licenseId: 1n,
    fromDigest: `0x${'11'.repeat(32)}`,
    toDigest: RUNNING_COMPOSE,
    instanceId: toBytes32(RAW_INSTANCE_ID),
    nonce: 1n,
    expiry: 1_600n,
  };

  const run = async (authorization: MigrationAuthorization) => {
    const signature = await HOLDER.signTypedData({
      domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
      types: MIGRATION_AUTHORIZATION_TYPES,
      primaryType: 'MigrationAuthorization',
      message: authorization,
    });
    return migrate(
      {authorization, signature, signer: HOLDER.address},
      {config: CONFIG, client: client(), guestAgent: guestAgent(), store, now: () => 1_000n},
    );
  };

  const first = await run(base);
  assert.equal(first.status, 'complete');
  assert.equal(first.idempotentReplay, false);

  // Same nonce, genuinely different transition, genuinely signed. Keyed on the nonce this returned
  // `complete` while the transform never ran — the volume left un-migrated under code expecting the
  // new schema, and the upgrade flow recording success.
  const different = await run({...base, fromDigest: `0x${'22'.repeat(32)}`});
  assert.equal(different.idempotentReplay, false, 'a different authorization must not short-circuit');
});
