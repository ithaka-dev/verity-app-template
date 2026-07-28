/**
 * Schema migrations, and the idempotency they are required to have.
 *
 * ## The platform may retry, so "ran once" is not something you may assume
 *
 * A migration is signalled across a chain-and-enclave boundary. Exactly-once delivery across that
 * boundary is not achievable, and the honest move is to require idempotency of apps rather than
 * promise a guarantee that quietly does not hold. An app written assuming exactly-once is worse off
 * than one written with no guarantee at all, because it will look correct until the first retry.
 *
 * ## Two mechanisms, because either alone is insufficient
 *
 * **1. A journal**, so a completed migration short-circuits on retry.
 * **2. Transforms that tolerate re-application**, so a retry that beats the journal is still safe.
 *
 * The second is not redundant with the first, and this is the part that is easy to get wrong.
 * Consider the ordering:
 *
 * ```
 * transform data        ← succeeds, volume now holds v2
 * write journal entry   ← process dies here
 * ```
 *
 * On retry the journal says nothing happened, so the transform runs again — against data that is
 * already migrated. If the transform is not idempotent, the second pass corrupts it. The journal
 * narrows the window; it cannot close it, because there is no way to make "transform" and "record
 * that we transformed" a single atomic act across two files.
 *
 * So transforms here are written to be safe when applied to already-migrated data, and the
 * `schemaVersion` stored *in the document* is what makes that checkable rather than hoped for.
 */

import type {JsonStore, VersionedDocument} from './store.ts';

/** A record in schema v1. */
export interface ProfileV1 {
  readonly id: string;
  /** A single display name. */
  readonly name: string;
}

/** A record in schema v2: the name is split, and a created timestamp is introduced. */
export interface ProfileV2 {
  readonly id: string;
  readonly givenName: string;
  readonly familyName: string;
}

export interface ProfilesV1 {
  readonly profiles: readonly ProfileV1[];
}
export interface ProfilesV2 {
  readonly profiles: readonly ProfileV2[];
}

export const CURRENT_SCHEMA_VERSION = 2;
export const PROFILES_DOCUMENT = 'profiles';

/**
 * A single schema step.
 *
 * Steps are one-way. There is no `down`, and that is a deliberate limitation rather than an
 * omission: **backward state migration is not realistic** — v1 cannot read what v2 wrote, and no
 * hook runs in reverse. Where a developer permits rollback, the holder gets the old *version* with
 * *fresh* state, and they must be told that before they choose it.
 */
export interface SchemaStep {
  readonly from: number;
  readonly to: number;
  readonly apply: (data: unknown) => unknown;
}

/**
 * v1 → v2: split `name` into `givenName` / `familyName`.
 *
 * Idempotent by construction: a record that already has `givenName` is passed through untouched.
 * Without that check, a second application would read `name` as `undefined` and overwrite good
 * data with empty strings — the exact damage a retry is supposed to be harmless.
 */
export const splitName: SchemaStep = {
  from: 1,
  to: 2,
  apply(data: unknown): ProfilesV2 {
    const profiles = (data as ProfilesV1 | ProfilesV2).profiles ?? [];
    return {
      profiles: profiles.map((profile) => {
        if (isAlreadyV2(profile)) return profile;
        const [givenName = '', ...rest] = profile.name.trim().split(/\s+/);
        return {id: profile.id, givenName, familyName: rest.join(' ')};
      }),
    };
  },
};

function isAlreadyV2(profile: ProfileV1 | ProfileV2): profile is ProfileV2 {
  return typeof (profile as ProfileV2).givenName === 'string';
}

/** Ordered by `from`; each step's `to` must be the next step's `from`. */
export const SCHEMA_STEPS: readonly SchemaStep[] = [splitName];

/** No path exists from the stored schema version to the one this app expects. */
export class NoMigrationPathError extends Error {
  readonly from: number;
  readonly to: number;

  constructor(from: number, to: number) {
    super(`no migration path from schema v${from} to v${to}`);
    this.name = 'NoMigrationPathError';
    this.from = from;
    this.to = to;
  }
}

export interface MigrationOutcome {
  readonly fromSchema: number;
  readonly toSchema: number;
  /** False when the data was already at the target version — a retry, or a no-op upgrade. */
  readonly changed: boolean;
}

/**
 * Bring the stored document up to `targetVersion`.
 *
 * Safe to call repeatedly. Calling it on already-migrated data reports `changed: false` and writes
 * nothing.
 */
export async function migrateProfiles(
  store: JsonStore,
  targetVersion: number = CURRENT_SCHEMA_VERSION,
): Promise<MigrationOutcome> {
  const document = await store.read<unknown>(PROFILES_DOCUMENT);

  // Nothing stored yet. A fresh instance is already at the current schema by definition — there is
  // no data to transform — so this is a success, not an error.
  if (document === undefined) {
    await store.write(PROFILES_DOCUMENT, {
      schemaVersion: targetVersion,
      data: {profiles: []} satisfies ProfilesV2,
    });
    return {fromSchema: targetVersion, toSchema: targetVersion, changed: false};
  }

  const startVersion = document.schemaVersion;
  if (startVersion === targetVersion) {
    return {fromSchema: startVersion, toSchema: targetVersion, changed: false};
  }
  if (startVersion > targetVersion) {
    // Running an older app against newer data. Refuse loudly rather than "migrating" downward and
    // discarding fields the older version does not know about.
    throw new NoMigrationPathError(startVersion, targetVersion);
  }

  let current: unknown = document.data;
  let version = startVersion;
  while (version < targetVersion) {
    const step = SCHEMA_STEPS.find((candidate) => candidate.from === version);
    if (step === undefined) throw new NoMigrationPathError(version, targetVersion);
    current = step.apply(current);
    version = step.to;
  }

  const migrated: VersionedDocument<unknown> = {schemaVersion: version, data: current};
  await store.write(PROFILES_DOCUMENT, migrated);
  return {fromSchema: startVersion, toSchema: version, changed: true};
}
