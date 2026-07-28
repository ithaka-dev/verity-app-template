/**
 * `migrate` — transform this instance's data for a new version.
 *
 * ## The order of checks is the security model
 *
 * 1. The authorization describes *this* instance, *this* transition, and has not expired.
 * 2. Its signature is genuine, dispatching on account type.
 * 3. The signer **currently** holds the licence, read from chain state.
 * 4. Only then, touch data.
 *
 * Step 3 cannot be cached, skipped, or replaced with a deploy-time owner. Licences transfer
 * (§2.6), so a previous holder would otherwise keep the ability to authorize migrations on an
 * instance they sold.
 *
 * Nothing here trusts the orchestrator. It relays a holder-signed fact and observes the result;
 * it does not author anything. A secure channel to the orchestrator would not change this — an
 * authenticated channel establishes *who is speaking*, not *that what they say is authorized*.
 *
 * ## The result is tri-state, not a boolean
 *
 * `complete` / `failed` / `needs_holder_action`. The third exists so an app that must ask its owner
 * something — a destructive transformation, a choice between schemas — can say so instead of
 * guessing or failing. The platform does not mandate holder involvement; it makes holder
 * involvement *sayable*.
 *
 * `needs_holder_action` reaches the holder through the orchestrator and the upgrade flow, never
 * directly — the app sits inside a CVM behind an endpoint the holder may never call. It must also
 * be emitted as telemetry: an instance parked in `needs_holder_action` is indistinguishable from a
 * slow migration until somebody looks.
 */

import type {Address, Hex, PublicClient} from 'viem';

import {assertAuthorizationMatches, type MigrationAuthorization} from '../authorization.ts';
import type {AppConfig} from '../config.ts';
import type {GuestAgent} from '../guest-agent.ts';
import {assertCurrentHolder} from '../holder.ts';
import {fingerprint, log} from '../logging.ts';
import {verifyMigrationSignature} from '../signature.ts';
import {readPreviousComposeHash} from '../state/boot-record.ts';
import {migrateProfiles} from '../state/migrations.ts';
import type {JsonStore} from '../state/store.ts';
import {readJournal, recordAttempt, recordOutcome} from './journal.ts';

export type MigrateStatus = 'complete' | 'failed' | 'needs_holder_action';

export interface MigrateResult {
  readonly status: MigrateStatus;
  /** Human-readable, and safe to surface: never contains state or secrets. */
  readonly detail: string;
  /** True when this call short-circuited on a previously recorded outcome. */
  readonly idempotentReplay: boolean;
}

export interface MigrateRequest {
  readonly authorization: MigrationAuthorization;
  readonly signature: Hex;
  /** The account claimed to have signed. Verified, never trusted. */
  readonly signer: Address;
}

export interface MigrateDependencies {
  readonly config: AppConfig;
  readonly client: PublicClient;
  readonly guestAgent: GuestAgent;
  readonly store: JsonStore;
  /** Injected so the handler stays pure and testable. */
  readonly now: () => bigint;
}

export async function migrate(
  request: MigrateRequest,
  dependencies: MigrateDependencies,
): Promise<MigrateResult> {
  const {config, client, guestAgent, store, now} = dependencies;
  const {authorization, signature, signer} = request;

  const info = await guestAgent.info();
  const instanceId = toBytes32(info.instanceId);

  // Fail closed. Without the running compose hash there is nothing to compare `toDigest` against,
  // and the check would degrade to "the message agrees with itself" — which passes for any
  // authorization at all. `health` tolerates a missing compose hash because liveness does not
  // depend on it; mutating the holder's data does.
  if (info.composeHash === '') {
    return failed(
      'guest agent did not report a compose hash, so `toDigest` cannot be verified against ' +
        'what is actually running; refusing to migrate',
    );
  }

  // — 1. Does this authorization describe the situation it arrived in? —
  try {
    assertAuthorizationMatches(
      authorization,
      {
        runningComposeHash: toBytes32(info.composeHash),
        previousComposeHash: await readPreviousComposeHash(store),
        instanceId,
      },
      now(),
    );
  } catch (err) {
    return failed(`authorization rejected: ${(err as Error).message}`);
  }

  // — 2. Is the signature genuine? —
  try {
    await verifyMigrationSignature({
      client,
      signer,
      authorization,
      chainId: config.chainId,
      licenseToken: config.licenseToken,
      signature,
    });
  } catch (err) {
    return failed(`signature rejected: ${(err as Error).message}`);
  }

  // — 3. Does the signer hold the licence *now*? —
  try {
    await assertCurrentHolder({client, config, signer});
  } catch (err) {
    return failed(`holder check failed: ${(err as Error).message}`);
  }

  // — Idempotency: has this exact authorization already been carried out? —
  //
  // Keyed on the nonce, which the holder signed, so a retry of the same authorization is
  // recognisable and a genuinely new request is not mistaken for one.
  const journal = await readJournal(store);
  const previous = journal[authorization.nonce.toString()];
  if (previous?.status === 'complete') {
    log('migrate_replay', {nonce: authorization.nonce.toString()});
    return {
      status: 'complete',
      detail: 'already migrated under this authorization',
      idempotentReplay: true,
    };
  }

  // Recorded *before* the transform, so a crash between transform and outcome leaves evidence that
  // an attempt was in flight. It does not make the pair atomic — nothing can — which is why the
  // transforms are also written to tolerate re-application. See `state/migrations.ts`.
  await recordAttempt(store, authorization.nonce, {
    fromDigest: authorization.fromDigest,
    toDigest: authorization.toDigest,
  });

  // — 4. Only now, touch data. —
  try {
    const outcome = await migrateProfiles(store);
    await recordOutcome(store, authorization.nonce, 'complete');

    log('migrate_complete', {
      nonce: authorization.nonce.toString(),
      from_schema: outcome.fromSchema,
      to_schema: outcome.toSchema,
      changed: outcome.changed,
      signature_fp: fingerprint('holder-signature', signature),
    });

    return {
      status: 'complete',
      detail: outcome.changed
        ? `migrated schema v${outcome.fromSchema} to v${outcome.toSchema}`
        : `already at schema v${outcome.toSchema}; nothing to transform`,
      idempotentReplay: false,
    };
  } catch (err) {
    await recordOutcome(store, authorization.nonce, 'failed');
    return failed(`migration failed: ${(err as Error).message}`);
  }
}

function failed(detail: string): MigrateResult {
  log('migrate_failed', {detail});
  return {status: 'failed', detail, idempotentReplay: false};
}

/**
 * The guest agent reports `instance_id` as a hex string of unspecified width; the signed struct
 * needs a `bytes32`. Left-pad rather than hash, so the value stays legible in a signing prompt —
 * EIP-712 renders the struct to a human, and an opaque digest there defeats the point of a holder
 * being able to see what they are authorizing.
 */
export function toBytes32(value: string): Hex {
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (hex.length > 64) throw new Error(`instance id ${value} does not fit in bytes32`);
  return `0x${hex.padStart(64, '0')}` as Hex;
}
