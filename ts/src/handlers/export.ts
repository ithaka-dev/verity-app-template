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
 */

import type {Address, Hex, PublicClient} from 'viem';

import {assertExportAuthorizationMatches, type ExportAuthorization} from '../authorization.ts';
import type {AppConfig} from '../config.ts';
import type {GuestAgent} from '../guest-agent.ts';
import {assertCurrentHolder} from '../holder.ts';
import {fingerprint, log} from '../logging.ts';
import {parseRecipientKey, seal, type SealedBundle} from '../seal.ts';
import {verifyExportSignature} from '../signature.ts';
import {PROFILES_DOCUMENT} from '../state/migrations.ts';
import type {JsonStore} from '../state/store.ts';
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

  // — 4. Read, then seal before anything leaves. —
  try {
    const recipient = parseRecipientKey(authorization.recipientPublicKey);
    const plaintext = await collectState(store);
    const bundle = seal(plaintext, recipient, {
      licenseId: authorization.licenseId,
      instanceId: info.instanceId,
    });

    log('export_complete', {
      nonce: authorization.nonce.toString(),
      bytes: plaintext.length,
      // The recipient key is public, but fingerprinting keeps the log line uniform and makes an
      // unexpected recipient visible as a changed value rather than a wall of hex.
      recipient_fp: fingerprint('export-key', authorization.recipientPublicKey),
    });

    return {status: 'complete', detail: 'state sealed to the holder key', bundle};
  } catch (err) {
    return failed(`export failed: ${(err as Error).message}`);
  }
}

function failed(detail: string): ExportResult {
  log('export_failed', {detail});
  return {status: 'failed', detail};
}
