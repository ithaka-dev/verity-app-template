/**
 * The app's state, on the encrypted volume.
 *
 * ## What the volume is, and what carries across an upgrade
 *
 * An in-place upgrade preserves `app_id`, `instance_id` and **the encrypted volume itself** (ADR
 * 0008, measured on real TDX). So `migrate` exists to *transform* data, never to move it — the
 * bytes are already there when the new version starts.
 *
 * This matters because the failure mode of getting it wrong is silent. A *fresh deploy* produces a
 * working instance with a new `app_id`, which derives different keys, which cannot read anything
 * the previous instance wrote. Nothing errors. Nothing in the attestation is wrong. The holder gets
 * a healthy empty app and finds out later.
 *
 * ## Atomic writes, because the platform may retry
 *
 * Every write goes to a temporary file and is renamed over the target. `rename` within a
 * filesystem is atomic, so a crash — or a platform retry that arrives mid-write — leaves either
 * the old complete file or the new complete file, never half of either. A plain in-place write can
 * leave truncated JSON that no version can read, which turns a retryable failure into a permanent
 * one.
 */

import {mkdir, readFile, rename, writeFile} from 'node:fs/promises';
import {dirname, join} from 'node:path';

/** Where the encrypted volume is mounted. Pinned in the compose alongside everything else. */
export const DEFAULT_DATA_DIR = process.env.VERITY_DATA_DIR ?? '/data';

/** Stored state could not be read or is not the shape this version expects. */
export class StoreError extends Error {
  constructor(path: string, detail: string) {
    super(`state at ${path}: ${detail}`);
    this.name = 'StoreError';
  }
}

/**
 * A JSON document with an explicit schema version.
 *
 * The version is stored *in the data*, not inferred from the app version. An app that infers it
 * cannot tell an un-migrated volume from a migrated one after a retry, and cannot tell either from
 * a rollback where the holder is deliberately running an older version against fresh state.
 */
export interface VersionedDocument<T> {
  readonly schemaVersion: number;
  readonly data: T;
}

export class JsonStore {
  private readonly dataDir: string;

  constructor(dataDir: string = DEFAULT_DATA_DIR) {
    this.dataDir = dataDir;
  }

  private pathFor(name: string): string {
    return join(this.dataDir, `${name}.json`);
  }

  /** Read a document, or `undefined` if it has never been written. */
  async read<T>(name: string): Promise<VersionedDocument<T> | undefined> {
    const path = this.pathFor(name);
    let raw: string;
    try {
      raw = await readFile(path, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new StoreError(path, (err as Error).message);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      // Refuse rather than treat unreadable state as absent. Returning `undefined` here would let
      // a corrupt volume look like a fresh one, and the app would cheerfully start over on top of
      // the holder's data.
      throw new StoreError(path, `is not valid JSON (${(err as Error).message})`);
    }

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof (parsed as VersionedDocument<T>).schemaVersion !== 'number'
    ) {
      throw new StoreError(path, 'has no numeric schemaVersion');
    }
    return parsed as VersionedDocument<T>;
  }

  /** Write a document atomically. */
  async write<T>(name: string, document: VersionedDocument<T>): Promise<void> {
    const path = this.pathFor(name);
    await mkdir(dirname(path), {recursive: true});
    const temporary = `${path}.tmp`;
    await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
    await rename(temporary, path);
  }
}
