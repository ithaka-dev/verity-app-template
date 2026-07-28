/**
 * `export` — hand the holder their own data, sealed to a key only they hold.
 *
 * ## What this capability is for
 *
 * Spec §2.6 promises "a durable, owned, transferable possession." Ownership that cannot survive the
 * custodian is not ownership; it is very good tenancy (ADR 0010). The scenarios are ordinary — a
 * provider exits a region, a holder moves to another TEE provider, an account is suspended in error,
 * or someone just wants a backup — and every one is answered by this.
 *
 * ## Same check order as `migrate`, and for the same reasons
 *
 * 1. The authorization describes *this* instance and has not expired.
 * 2. Its signature is genuine, dispatching on account type.
 * 3. The signer **currently** holds the licence, read from chain state.
 * 4. Only then, read data — and seal it before it leaves.
 *
 * Step 3 is not optional here either. Licences transfer (§2.6), so a deploy-time owner would let a
 * *previous* holder export the data of an instance they sold. That is a data breach with a valid
 * signature on it.
 *
 * ## No auto-export, in any form
 *
 * Never on a schedule, never because an orchestrator asked, never as a side effect of an upgrade.
 * This extends I10's reasoning: the holder's data leaving the enclave is a distinct act requiring
 * its own consent, and an app that exports unasked has made itself the thing the architecture
 * exists to prevent.
 *
 * If you add a "backup" feature to an app built on this template, it is authorized per export or it
 * is not authorized.
 *
 * ## One signature, one export
 *
 * The authorization is journalled and refused on reuse, for the same reason `migrate` is. Without
 * that, a single signature was a **standing tap on live state**: replaying it returned *current*
 * data, not a cached copy, so the holder signed one act and issued a continuous read capability —
 * held by the orchestrator, which spec §2.8 says must become untrusted. Bundles are sealed to the
 * holder's key so the orchestrator cannot read them today, but it could retain every one, and a
 * later compromise of the holder's backup key would open the whole series at once.
 */

import type {Address, Hex, PublicClient} from 'viem';

import {
  assertExportAuthorizationMatches,
  hashExportAuthorization,
  type ExportAuthorization,
} from '../authorization.ts';
import type {AppConfig} from '../config.ts';
import type {GuestAgent} from '../guest-agent.ts';
import {assertCurrentHolder} from '../holder.ts';
import {fingerprint, log} from '../logging.ts';
import {parseRecipientKey, seal, type SealedBundle} from '../seal.ts';
import {verifyExportSignature} from '../signature.ts';
import {PROFILES_DOCUMENT} from '../state/migrations.ts';
import type {JsonStore} from '../state/store.ts';
import {readJournal, recordAttempt, recordOutcome} from './journal.ts';
import {toBytes32} from './migrate.ts';

export type ExportStatus = 'complete' | 'failed';

export interface ExportResult {
  readonly status: ExportStatus;
  readonly detail: string;
  /** Present only on success. Sealed — this is safe to hand to a relayer. */
  readonly bundle?: SealedBundle;
}

export interface ExportRequest {
  readonly authorization: ExportAuthorization;
  readonly signature: Hex;
  /** The account claimed to have signed. Verified, never trusted. */
  readonly signer: Address;
}

export interface ExportDependencies {
  readonly config: AppConfig;
  readonly client: PublicClient;
  readonly guestAgent: GuestAgent;
  readonly store: JsonStore;
  readonly now: () => bigint;
}

/**
 * **The app decides what its state is.** Only it knows. The platform supplies the moment and the
 * authorization; the app supplies the meaning — the same division of labour as `migrate`.
 *
 * Replace this when you adapt the template. Include everything the holder would need to reconstitute
 * their data elsewhere, and nothing that is not theirs: no derived keys, no platform credentials, no
 * other holder's records. A bundle is only as good as what someone thought to put in it, and a
 * holder discovers an omission at the worst possible moment.
 */
async function collectState(store: JsonStore): Promise<Uint8Array> {
  const profiles = await store.read<unknown>(PROFILES_DOCUMENT);
  const bundle = {
    exportedDocuments: {
      [PROFILES_DOCUMENT]: profiles ?? null,
    },
  };
  return new TextEncoder().encode(JSON.stringify(bundle, null, 2));
}

export async function exportState(
  request: ExportRequest,
  dependencies: ExportDependencies,
): Promise<ExportResult> {
  const {config, client, guestAgent, store, now} = dependencies;
  const {authorization, signature, signer} = request;

  const info = await guestAgent.info();
  const journalKey = hashExportAuthorization(authorization, config.chainId, config.licenseToken);

  // — 1. Does this authorization describe this instance, now? —
  try {
    assertExportAuthorizationMatches(authorization, toBytes32(info.instanceId), now());
  } catch (err) {
    return failed(`authorization rejected: ${(err as Error).message}`);
  }

  // — 2. Is the signature genuine? —
  try {
    await verifyExportSignature({
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

  // — Idempotency, and more importantly non-replay. Unlike `migrate`, a repeated export is not
  // harmless: it returns whatever the state is *now*, so honouring a replay would extend a
  // one-time consent into a standing one.
  const journal = await readJournal(store);
  if (journal[journalKey] !== undefined) {
    return failed(
      'this export authorization has already been used; a signature authorizes one export, not ' +
        'continuing access',
      'replayed',
    );
  }
  await recordAttempt(store, journalKey, {
    fromDigest: authorization.recipientPublicKey,
    toDigest: authorization.recipientPublicKey,
  });

  // — 4. Read, then seal before anything leaves. —
  try {
    const recipient = parseRecipientKey(authorization.recipientPublicKey);
    const plaintext = await collectState(store);
    // The **canonical** instance id — the value the holder signed — not the raw guest-agent
    // string. The context is baked into the HKDF `info`, so sealing against the raw form produced
    // a bundle whose context a holder-side tool could not reconstruct: dStack reports
    // `instance_id` as bare 20-byte hex with no `0x`, and the signed value is the padded bytes32.
    // The holder could not open their own export, and would discover it when they needed the data.
    const bundle = seal(plaintext, recipient, {
      licenseId: authorization.licenseId,
      instanceId: toBytes32(info.instanceId),
    });
    await recordOutcome(store, journalKey, 'complete');

    log('export_complete', {
      authorization: journalKey,
      // The recipient key is public, but fingerprinting keeps the log line uniform and makes an
      // unexpected recipient visible as a changed value rather than a wall of hex.
      recipient_fp: fingerprint('export-key', authorization.recipientPublicKey),
    });

    return {status: 'complete', detail: 'state sealed to the holder key', bundle};
  } catch (err) {
    await recordOutcome(store, journalKey, 'failed');
    return failed(`export failed: ${(err as Error).message}`, (err as Error).name);
  }
}

/**
 * @param detail returned to the caller
 * @param reason a stable, log-safe label — a caught message may quote holder state or a path, and
 *   `public_logs` defaults to true
 */
function failed(detail: string, reason = 'rejected'): ExportResult {
  log('export_failed', {reason});
  return {status: 'failed', detail};
}
