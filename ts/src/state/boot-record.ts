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
  /**
   * The licence this instance serves, as a decimal string.
   *
   * **Bound by the first authorization the instance accepts, and never changed after.** Holding a
   * licence for this app is not the same as holding *this instance's* licence: without this, any
   * customer of the version could act on any other customer's instance, because a chain balance
   * cannot say which of several identical instances a licence backs.
   *
   * The chain knows who owns each licence; only the volume can know which licence this instance
   * was provisioned for. That is why the binding lives here rather than being derived.
   *
   * **Transfer.** Selling the licence moves it on chain, and the new holder passes the same
   * `licenseId` — so migration and export keep working for them, and stop working for the seller,
   * with no re-binding act. That is §2.6's "transfer the token, transfer the living instance"
   * holding literally.
   */
  readonly licenseId?: string;
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

/** The licence this instance serves, or `null` before it has been bound. */
export async function readBoundLicenseId(store: JsonStore): Promise<bigint | null> {
  const document = await store.read<BootRecord>(BOOT_RECORD_DOCUMENT);
  const raw = document?.data.licenseId;
  return raw === undefined ? null : BigInt(raw);
}

/**
 * Bind this instance to a licence, if it is not bound already.
 *
 * First write wins. A later authorization naming a different licence is refused rather than
 * rebinding — otherwise the "which instance is this" question would be answerable by whoever asked
 * most recently, which is no answer at all.
 */
export async function bindLicenseId(store: JsonStore, licenseId: bigint): Promise<void> {
  const existing = await store.read<BootRecord>(BOOT_RECORD_DOCUMENT);
  if (existing?.data.licenseId !== undefined) return;
  await store.write(BOOT_RECORD_DOCUMENT, {
    schemaVersion: BOOT_RECORD_SCHEMA_VERSION,
    data: {composeHash: existing?.data.composeHash ?? ('0x' as Hex), licenseId: licenseId.toString()},
  });
}
