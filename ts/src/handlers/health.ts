/**
 * `health` — is this instance up and serving.
 *
 * Level 1 of the conformance tiers. Cheap, and the orchestrator needs a readiness signal anyway;
 * it is also the verify step of a migration, which is why it reports the schema version rather
 * than just `ok`.
 *
 * ## Deliberately says nothing about whether the app is *authentic*
 *
 * A healthy response is not evidence that the right code is running — this handler is part of the
 * app, so a substituted app would happily report itself healthy. That question is answered by
 * attestation, against the raw quote, by `verity-verifier`. Do not let a health check drift into
 * looking like a trust signal; report liveness, and leave authenticity to the mechanism that can
 * actually establish it.
 */

import type {GuestAgent} from '../guest-agent.ts';
import {CURRENT_SCHEMA_VERSION, PROFILES_DOCUMENT} from '../state/migrations.ts';
import type {JsonStore} from '../state/store.ts';

export type HealthStatus = 'ok' | 'degraded';

export interface HealthResult {
  readonly status: HealthStatus;
  readonly appId: string;
  readonly instanceId: string;
  /** The app version, from the measured compose. */
  readonly version: string;
  /** What the stored data is at; `null` when nothing has been written yet. */
  readonly schemaVersion: number | null;
  /** The schema this build expects. A mismatch means a migration is outstanding. */
  readonly expectedSchemaVersion: number;
  /** Set when `status` is `degraded`, so an operator does not have to guess. */
  readonly detail?: string;
}

export interface HealthDependencies {
  readonly guestAgent: GuestAgent;
  readonly store: JsonStore;
  readonly version: string;
}

/**
 * Report liveness.
 *
 * `degraded` rather than a thrown error when state is unreadable: the instance is genuinely
 * running and the orchestrator's next move differs from the one it would make for a dead instance.
 * Collapsing the two would hide which happened.
 */
export async function health(dependencies: HealthDependencies): Promise<HealthResult> {
  const {guestAgent, store, version} = dependencies;
  const info = await guestAgent.info();

  const base = {
    appId: info.appId,
    instanceId: info.instanceId,
    version,
    expectedSchemaVersion: CURRENT_SCHEMA_VERSION,
  } as const;

  try {
    const document = await store.read<unknown>(PROFILES_DOCUMENT);
    const schemaVersion = document?.schemaVersion ?? null;
    if (schemaVersion !== null && schemaVersion !== CURRENT_SCHEMA_VERSION) {
      return {
        ...base,
        status: 'degraded',
        schemaVersion,
        detail: `stored schema is v${schemaVersion}, this build expects v${CURRENT_SCHEMA_VERSION}; migration outstanding`,
      };
    }
    return {...base, status: 'ok', schemaVersion};
  } catch (err) {
    return {
      ...base,
      status: 'degraded',
      schemaVersion: null,
      detail: `state unreadable: ${(err as Error).message}`,
    };
  }
}
