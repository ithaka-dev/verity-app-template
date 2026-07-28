import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';

import {
  CURRENT_SCHEMA_VERSION,
  NoMigrationPathError,
  PROFILES_DOCUMENT,
  migrateProfiles,
  splitName,
  type ProfilesV2,
} from '../src/state/migrations.ts';
import {JsonStore, StoreError} from '../src/state/store.ts';

async function freshStore(): Promise<{store: JsonStore; dir: string}> {
  const dir = await mkdtemp(join(tmpdir(), 'verity-template-'));
  return {store: new JsonStore(dir), dir};
}

test('migrates v1 data to v2', async () => {
  const {store} = await freshStore();
  await store.write(PROFILES_DOCUMENT, {
    schemaVersion: 1,
    data: {profiles: [{id: 'a', name: 'Ada Lovelace'}]},
  });

  const outcome = await migrateProfiles(store);
  assert.equal(outcome.changed, true);
  assert.equal(outcome.toSchema, CURRENT_SCHEMA_VERSION);

  const document = await store.read<ProfilesV2>(PROFILES_DOCUMENT);
  assert.deepEqual(document?.data.profiles, [{id: 'a', givenName: 'Ada', familyName: 'Lovelace'}]);
});

/**
 * The property the platform's retry behaviour depends on. Not "it does not crash" — the data must
 * be *identical*, because a second pass that mangles already-migrated records is the exact damage a
 * retry is supposed to be harmless.
 */
test('migrating twice produces identical data', async () => {
  const {store} = await freshStore();
  await store.write(PROFILES_DOCUMENT, {
    schemaVersion: 1,
    data: {profiles: [{id: 'a', name: 'Ada Lovelace'}, {id: 'b', name: 'Grace'}]},
  });

  await migrateProfiles(store);
  const afterFirst = await store.read<ProfilesV2>(PROFILES_DOCUMENT);

  const second = await migrateProfiles(store);
  const afterSecond = await store.read<ProfilesV2>(PROFILES_DOCUMENT);

  assert.equal(second.changed, false, 'second run must be a no-op');
  assert.deepEqual(afterSecond, afterFirst);
});

/**
 * The window the journal cannot close: the transform succeeded, the journal write did not, and the
 * retry runs the transform against already-migrated data. This is the case that makes idempotent
 * transforms mandatory rather than merely tidy.
 */
test('the transform is safe when applied directly to already-migrated data', () => {
  const migrated = {profiles: [{id: 'a', givenName: 'Ada', familyName: 'Lovelace'}]};
  assert.deepEqual(splitName.apply(migrated), migrated);
});

test('a name with no surname migrates without inventing one', () => {
  const result = splitName.apply({profiles: [{id: 'b', name: 'Grace'}]}) as ProfilesV2;
  assert.deepEqual(result.profiles, [{id: 'b', givenName: 'Grace', familyName: ''}]);
});

test('a fresh volume is initialised at the current schema', async () => {
  const {store} = await freshStore();
  const outcome = await migrateProfiles(store);
  assert.equal(outcome.changed, false);
  const document = await store.read<ProfilesV2>(PROFILES_DOCUMENT);
  assert.equal(document?.schemaVersion, CURRENT_SCHEMA_VERSION);
});

/**
 * An older build against newer data. Refuse rather than "migrate" downward — the older version
 * does not know the fields it would be discarding.
 */
test('refuses to migrate backwards', async () => {
  const {store} = await freshStore();
  await store.write(PROFILES_DOCUMENT, {schemaVersion: 99, data: {profiles: []}});
  await assert.rejects(() => migrateProfiles(store), NoMigrationPathError);
});

test('refuses to migrate across a gap with no step', async () => {
  const {store} = await freshStore();
  await store.write(PROFILES_DOCUMENT, {schemaVersion: 0, data: {profiles: []}});
  await assert.rejects(() => migrateProfiles(store), NoMigrationPathError);
});

/**
 * Corrupt state must not look like a fresh volume. If it did, the app would start over on top of
 * the holder's data and report success.
 */
test('unreadable state is refused, not treated as absent', async () => {
  const {store, dir} = await freshStore();
  await writeFile(join(dir, `${PROFILES_DOCUMENT}.json`), '{not json', 'utf8');
  await assert.rejects(() => store.read(PROFILES_DOCUMENT), StoreError);
});

test('state without a schemaVersion is refused', async () => {
  const {store, dir} = await freshStore();
  await writeFile(join(dir, `${PROFILES_DOCUMENT}.json`), '{"data":{}}', 'utf8');
  await assert.rejects(() => store.read(PROFILES_DOCUMENT), StoreError);
});

test('writes leave no temporary file behind', async () => {
  const {store, dir} = await freshStore();
  await store.write(PROFILES_DOCUMENT, {schemaVersion: 2, data: {profiles: []}});
  await assert.rejects(
    () => readFile(join(dir, `${PROFILES_DOCUMENT}.json.tmp`), 'utf8'),
    /ENOENT/,
  );
});
