/**
 * What configuration this instance was running the last time it started.
 *
 * ## Why an app should record this
 *
 * A migration authorization names the version being migrated *from*. After an in-place upgrade the
 * instance has already restarted on the *new* configuration, so the platform can tell the app what
 * it is running now but has no memory of what it was running before. The only place that memory
 * can live is the volume — which survives the upgrade precisely because upgrade is in place
 * (ADR 0008).
 *
 * Without it, `fromDigest` is a field the app can only take on faith. With it, an authorization
 * naming the wrong source version is refused locally instead of relying solely on the signature
 * binding.
 *
 * ## Written after a successful start, not before
 *
 * If a build cannot start, its compose hash must not become the recorded "previous" — otherwise a
 * crash-looping version overwrites the last known-good source and the subsequent migration is
 * evaluated against a version that never really ran.
 */

import type {Hex} from 'viem';

import type {JsonStore} from './store.ts';

export const BOOT_RECORD_DOCUMENT = 'boot-record';
const BOOT_RECORD_SCHEMA_VERSION = 1;

export interface BootRecord {
  /** The compose hash observed at the most recent successful start. */
  readonly composeHash: Hex;
}

/** The previously recorded compose hash, or `null` on a first boot. */
export async function readPreviousComposeHash(store: JsonStore): Promise<Hex | null> {
  const document = await store.read<BootRecord>(BOOT_RECORD_DOCUMENT);
  return document?.data.composeHash ?? null;
}

/**
 * Record the currently running compose hash.
 *
 * A no-op when it is unchanged, so an ordinary restart does not overwrite the record of the
 * version an outstanding migration is supposed to be coming *from*.
 */
export async function recordBootComposeHash(store: JsonStore, composeHash: Hex): Promise<void> {
  const existing = await store.read<BootRecord>(BOOT_RECORD_DOCUMENT);
  if (existing?.data.composeHash?.toLowerCase() === composeHash.toLowerCase()) return;
  await store.write(BOOT_RECORD_DOCUMENT, {
    schemaVersion: BOOT_RECORD_SCHEMA_VERSION,
    data: {...existing?.data, composeHash},
  });
}

// The licence↔instance binding used to live here, set by the first authorization the instance
// accepted. It is on chain now (ADR 0024): the holder binds it in their own transaction, an
// instance can be claimed by only one licence ever, and the holder can verify it before trusting
// the instance. The volume version had a race nobody could see — whoever reached a fresh instance
// first owned it, silently and permanently, with no record anywhere to check.
