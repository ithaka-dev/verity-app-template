/**
 * The migration journal: what this instance has already been asked to do, and how it went.
 *
 * Keyed by the holder-signed nonce, so a retried authorization is recognisable while a genuinely
 * new request is not mistaken for one.
 *
 * ## What the journal does and does not buy
 *
 * It short-circuits a retry of an authorization that already completed. It does **not** make the
 * transform-then-record pair atomic, because two files cannot be written atomically together. A
 * crash between them leaves an `in_flight` entry and data that may already be transformed, and the
 * retry will run the transform again.
 *
 * That is why the transforms in `state/migrations.ts` are written to tolerate re-application, and
 * why the schema version lives inside the document. The journal narrows the window; the idempotent
 * transform is what makes the remaining window harmless. Relying on the journal alone is the
 * common mistake, and it fails exactly once, in production, on a retry.
 */

import type {Hex} from 'viem';

import type {JsonStore} from '../state/store.ts';

export const JOURNAL_DOCUMENT = 'migration-journal';
const JOURNAL_SCHEMA_VERSION = 1;

export type JournalStatus = 'in_flight' | 'complete' | 'failed';

export interface JournalEntry {
  readonly status: JournalStatus;
  readonly fromDigest: Hex;
  readonly toDigest: Hex;
}

/** Nonce (as a decimal string, since JSON has no bigint) to entry. */
export type Journal = Record<string, JournalEntry>;

export async function readJournal(store: JsonStore): Promise<Journal> {
  const document = await store.read<Journal>(JOURNAL_DOCUMENT);
  return document?.data ?? {};
}

async function writeJournal(store: JsonStore, journal: Journal): Promise<void> {
  await store.write(JOURNAL_DOCUMENT, {schemaVersion: JOURNAL_SCHEMA_VERSION, data: journal});
}

export async function recordAttempt(
  store: JsonStore,
  nonce: bigint,
  transition: {readonly fromDigest: Hex; readonly toDigest: Hex},
): Promise<void> {
  const journal = await readJournal(store);
  journal[nonce.toString()] = {status: 'in_flight', ...transition};
  await writeJournal(store, journal);
}

export async function recordOutcome(
  store: JsonStore,
  nonce: bigint,
  status: Exclude<JournalStatus, 'in_flight'>,
): Promise<void> {
  const journal = await readJournal(store);
  const existing = journal[nonce.toString()];
  if (existing === undefined) return;
  journal[nonce.toString()] = {...existing, status};
  await writeJournal(store, journal);
}
