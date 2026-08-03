/**
 * `health` — liveness, and deliberately nothing more.
 *
 * The module never appeared in the coverage report, because nothing imported it. It is level 1 of
 * the conformance tiers and the verify step of a migration, so an app that reports healthy when its
 * schema is behind would let an upgrade look finished when it is not.
 *
 * The property worth stating: **a healthy response is not evidence the right code is running.**
 * This handler is part of the app, so a substituted app reports itself healthy just as cheerfully.
 * Authenticity is attestation's job, against the raw quote.
 */

import assert from 'node:assert/strict';
import {mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';

import type {GuestAgent} from '../src/guest-agent.ts';
import {health} from '../src/handlers/health.ts';
import {CURRENT_SCHEMA_VERSION, PROFILES_DOCUMENT} from '../src/state/migrations.ts';
import {JsonStore} from '../src/state/store.ts';

const APP_ID = '465357ad5bfd16ef62f2c6a49204fe79affcfd05';
const INSTANCE_ID = 'e3f2a1b0c9d8e7f60514233241506978a9bacbdc';

function guestAgent(overrides: Partial<{appId: string; instanceId: string}> = {}): GuestAgent {
  return {
    info: async () => ({
      appId: overrides.appId ?? APP_ID,
      instanceId: overrides.instanceId ?? INSTANCE_ID,
      composeHash: `0x${'ab'.repeat(32)}`,
    }),
  } as unknown as GuestAgent;
}

async function freshStore(): Promise<JsonStore> {
  return new JsonStore(await mkdtemp(join(tmpdir(), 'verity-health-')));
}

test('a fresh instance is ok with no schema yet', async () => {
  const result = await health({guestAgent: guestAgent(), store: await freshStore(), version: '1.0.0'});

  assert.equal(result.status, 'ok');
  assert.equal(result.schemaVersion, null);
  assert.equal(result.expectedSchemaVersion, CURRENT_SCHEMA_VERSION);
  assert.equal(result.appId, APP_ID);
  assert.equal(result.instanceId, INSTANCE_ID);
  assert.equal(result.version, '1.0.0');
});

test('an instance at the current schema is ok', async () => {
  const store = await freshStore();
  await store.write(PROFILES_DOCUMENT, {schemaVersion: CURRENT_SCHEMA_VERSION, data: {profiles: []}});

  const result = await health({guestAgent: guestAgent(), store, version: '2.0.0'});
  assert.equal(result.status, 'ok');
  assert.equal(result.schemaVersion, CURRENT_SCHEMA_VERSION);
  assert.equal(result.detail, undefined);
});

/**
 * The signal that makes `health` the verify step of a migration: the instance is up, and its data
 * has not been transformed yet. Reporting plain `ok` here would let an upgrade look finished.
 */
test('an outstanding migration reports degraded, not ok', async () => {
  const store = await freshStore();
  await store.write(PROFILES_DOCUMENT, {schemaVersion: 1, data: {profiles: []}});

  const result = await health({guestAgent: guestAgent(), store, version: '2.0.0'});
  assert.equal(result.status, 'degraded');
  assert.equal(result.schemaVersion, 1);
  assert.match(result.detail ?? '', /migration outstanding/);
  // The detail must name both versions, or an operator cannot tell which way it is behind.
  assert.match(result.detail ?? '', /v1/);
  assert.match(result.detail ?? '', new RegExp(`v${CURRENT_SCHEMA_VERSION}`));
});

/**
 * Degraded rather than thrown: the instance is genuinely running, and the orchestrator's next move
 * differs from the one it would make for a dead instance. Collapsing the two would hide which
 * happened.
 */
test('unreadable state reports degraded rather than throwing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'verity-health-'));
  const store = new JsonStore(dir);
  const {writeFile} = await import('node:fs/promises');
  await writeFile(join(dir, `${PROFILES_DOCUMENT}.json`), '{not json', 'utf8');

  const result = await health({guestAgent: guestAgent(), store, version: '1.0.0'});
  assert.equal(result.status, 'degraded');
  assert.equal(result.schemaVersion, null);
  assert.match(result.detail ?? '', /state unreadable/);
});

test('identity comes from the platform, not from configuration', async () => {
  const result = await health({
    guestAgent: guestAgent({appId: 'other-app', instanceId: 'other-instance'}),
    store: await freshStore(),
    version: '1.0.0',
  });
  assert.equal(result.appId, 'other-app');
  assert.equal(result.instanceId, 'other-instance');
});

/** If the platform cannot be reached the app cannot answer for itself, and must not pretend to. */
test('an unreachable guest agent propagates rather than reporting healthy', async () => {
  const broken = {
    info: async () => {
      throw new Error('tappd.sock unreachable');
    },
  } as unknown as GuestAgent;

  const store = await freshStore();
  await assert.rejects(() => health({guestAgent: broken, store, version: '1.0.0'}), /unreachable/);
});
