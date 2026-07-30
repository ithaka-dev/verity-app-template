/**
 * Who currently holds the licence — resolved from chain state, every time.
 *
 * ## The mistake this module exists to prevent
 *
 * The instinct is to record the owner at deploy time and compare against that, calling the chain
 * only "if needed." **That is wrong, and it is wrong in a way that is invisible until someone is
 * harmed by it.**
 *
 * Spec §2.6 makes licences transferable on purpose: transfer the token, transfer the living
 * instance. So a baked-in owner means the **previous** holder can still sign valid migrations
 * after selling — and the new holder's instance obeys them. Every check passes. The signature is
 * genuine. The person authorizing the mutation sold the thing weeks ago.
 *
 * Ownership is chain state. Chain state is the only place to read it.
 *
 * ## Why `balanceOf`, not `ownerOf`
 *
 * Licences are ERC-1155, which has no `ownerOf` — several accounts can hold the same `tokenId`,
 * and under spec §2.9 each unit is a runnable instance. So the question this module answers is not
 * "who is the owner" but "does this signer hold this licence *now*", which is the question that
 * actually authorizes the act.
 */

import {createPublicClient, http, type Address, type Hex, type PublicClient} from 'viem';
import {encodeAbiParameters, keccak256, parseAbiParameters} from 'viem';

import type {AppConfig} from './config.ts';

/** The signer holds none of the licence they claim to be acting for. */
export class NotCurrentHolderError extends Error {
  readonly signer: Address;
  readonly tokenId: bigint;

  constructor(signer: Address, tokenId: bigint) {
    super(
      `${signer} holds none of licence ${tokenId}. Licences transfer (spec §2.6), so this may be ` +
        'a previous holder acting after a sale — which is exactly what resolving from chain ' +
        'state prevents.',
    );
    this.name = 'NotCurrentHolderError';
    this.signer = signer;
    this.tokenId = tokenId;
  }
}

const LICENSE_TOKEN_ABI = [
  {
    type: 'function',
    name: 'balanceOf',
    stateMutability: 'view',
    inputs: [
      {name: 'account', type: 'address'},
      {name: 'id', type: 'uint256'},
    ],
    outputs: [{name: '', type: 'uint256'}],
  },
  {
    type: 'function',
    name: 'instanceOf',
    stateMutability: 'view',
    inputs: [{name: 'licenseId', type: 'uint256'}],
    outputs: [{name: '', type: 'bytes32'}],
  },
] as const;

/**
 * The identifier of a *version* of an app. Groups licences; **is not one**.
 *
 * Mirrors `LicenseToken.versionIdFor`. Nothing is ever minted against it, and a balance of it means
 * nothing — that is the whole of ADR 0023. Use it to ask "which version is this licence for", never
 * to ask "does this address own this instance".
 *
 * Kept in sync with the contract by a shared test vector rather than by attention.
 */
export function versionIdFor(appManifest: Address, version: string): bigint {
  const versionHash = keccak256(new TextEncoder().encode(version));
  const encoded = encodeAbiParameters(parseAbiParameters('address, bytes32'), [
    appManifest,
    versionHash,
  ]);
  return BigInt(keccak256(encoded));
}

/** A client bound to the RPC endpoint pinned in the compose. */
export function createChainClient(config: AppConfig): PublicClient {
  return createPublicClient({
    transport: http(config.rpcUrl, {
      // Explicit, because "how long until we give up asking who owns this" is a property of the
      // app rather than of whichever transport version happens to be installed.
      timeout: 10_000,
      retryCount: 2,
    }),
  });
}

/**
 * Assert `signer` currently holds **this specific licence**.
 *
 * ## The question this asks, and the one it used to ask
 *
 * An earlier version checked `balanceOf(signer, versionIdFor(manifest, version))`. Licences were
 * fungible per version, so that established only that the signer was **a customer of this app
 * version** — and any customer could then act on any other customer's instance. A reviewer
 * demonstrated it end to end: buy your own licence at list price, sign an authorization naming
 * somebody else's instance, and the enclave sealed their data to your key. Every check passed.
 *
 * Licences are now per-unit (ADR 0023), so `balanceOf(signer, licenseId)` is 1 or 0 and answers
 * ownership of one entitlement. **`licenseId` must come from the signed authorization**, and the
 * caller must separately check it is the licence this instance serves — holding *a* licence is
 * still not the same as holding *this instance's* licence.
 *
 * @throws {NotCurrentHolderError} when the signer does not hold that licence
 */
export async function assertHoldsLicense(options: {
  readonly client: PublicClient;
  readonly config: AppConfig;
  readonly signer: Address;
  /** From the signed authorization. Never derived from a version. */
  readonly licenseId: bigint;
}): Promise<void> {
  const {client, config, signer, licenseId} = options;

  const balance = await client.readContract({
    address: config.licenseToken,
    abi: LICENSE_TOKEN_ABI,
    functionName: 'balanceOf',
    args: [signer, licenseId],
  });

  if (balance === 0n) throw new NotCurrentHolderError(signer, licenseId);
}

/** The licence has not been bound to any instance, so it cannot say which one is its own. */
export class InstanceNotBoundError extends Error {
  readonly licenseId: bigint;

  constructor(licenseId: bigint) {
    super(
      `licence ${licenseId} is not bound to an instance. The holder binds it themselves with ` +
        '`LicenseToken.bindInstance(licenseId, instanceId)` — until they do, this app cannot tell ' +
        'whose instance it is and refuses everything.',
    );
    this.name = 'InstanceNotBoundError';
    this.licenseId = licenseId;
  }
}

/**
 * Assert that `licenseId` is bound, on chain, to **this** instance.
 *
 * ## Why this reads from chain rather than from the volume
 *
 * An earlier version recorded the binding on the encrypted volume, set by the first authorization
 * the instance accepted. That worked and had a race nobody could see: whoever got an authorization
 * to a fresh instance first owned it, silently and permanently, with no record anywhere a holder
 * could check.
 *
 * On chain the binding is the **holder's own transaction** — the orchestrator is not involved and
 * cannot be, since it writes nothing to chain — an instance can be claimed by only one licence
 * ever, and a holder can verify the binding before trusting the instance. The theft that remains
 * possible is a visible event rather than an invisible one.
 *
 * **Both checks are required.** `assertHoldsLicense` says the signer owns the licence;
 * this says the licence owns this instance. The first without the second lets any holder of the
 * version act on any instance of it; the second without the first lets a stranger act on a bound
 * one.
 *
 * @throws {InstanceNotBoundError} the holder has not bound the licence yet
 * @throws {WrongInstanceLicenseError} the licence runs a different instance
 */
export async function assertLicenseRunsThisInstance(options: {
  readonly client: PublicClient;
  readonly config: AppConfig;
  readonly licenseId: bigint;
  /** This instance, canonicalised to the form the holder bound. */
  readonly instanceId: Hex;
}): Promise<void> {
  const {client, config, licenseId, instanceId} = options;

  const bound = await client.readContract({
    address: config.licenseToken,
    abi: LICENSE_TOKEN_ABI,
    functionName: 'instanceOf',
    args: [licenseId],
  });

  if (bound === `0x${'00'.repeat(32)}`) throw new InstanceNotBoundError(licenseId);
  if (bound.toLowerCase() !== instanceId.toLowerCase()) {
    throw new WrongInstanceLicenseError(bound, instanceId);
  }
}

/** The authorization names a licence other than the one this instance serves. */
export class WrongInstanceLicenseError extends Error {
  readonly boundInstance: Hex;
  readonly thisInstance: Hex;

  constructor(boundInstance: Hex, thisInstance: Hex) {
    super(
      `that licence runs instance ${boundInstance}, and this is ${thisInstance}. Holding a licence ` +
        'for this app is not the same as holding the one this instance runs under.',
    );
    this.name = 'WrongInstanceLicenseError';
    this.boundInstance = boundInstance;
    this.thisInstance = thisInstance;
  }
}

export type {Hex};
