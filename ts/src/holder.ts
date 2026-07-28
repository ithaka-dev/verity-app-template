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

const BALANCE_OF_ABI = [
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
] as const;

/**
 * The `tokenId` for a version of an app.
 *
 * Mirrors `LicenseToken.tokenIdFor` exactly: `keccak256(abi.encode(manifest, keccak256(version)))`.
 * `abi.encode`, never `encodePacked` — packed encoding of a dynamic type lets two different
 * `(manifest, version)` pairs collide, and a collision means one app's licence entitles a holder to
 * run another's.
 *
 * Kept in sync with the contract by a shared test vector rather than by attention.
 */
export function tokenIdFor(appManifest: Address, version: string): bigint {
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
 * Assert `signer` currently holds the licence for this app and version.
 *
 * @throws {NotCurrentHolderError} when the signer's balance is zero
 */
export async function assertCurrentHolder(options: {
  readonly client: PublicClient;
  readonly config: AppConfig;
  readonly signer: Address;
  /** Defaults to this app's own version; pass explicitly when checking the source of a migration. */
  readonly version?: string;
}): Promise<bigint> {
  const {client, config, signer} = options;
  const tokenId = tokenIdFor(config.appManifest, options.version ?? config.version);

  const balance = await client.readContract({
    address: config.licenseToken,
    abi: BALANCE_OF_ABI,
    functionName: 'balanceOf',
    args: [signer, tokenId],
  });

  if (balance === 0n) throw new NotCurrentHolderError(signer, tokenId);
  return balance;
}

/** Convenience for callers holding a `licenseId` directly rather than a version. */
export async function holdsLicense(
  client: PublicClient,
  licenseToken: Address,
  signer: Address,
  licenseId: bigint,
): Promise<boolean> {
  const balance = await client.readContract({
    address: licenseToken,
    abi: BALANCE_OF_ABI,
    functionName: 'balanceOf',
    args: [signer, licenseId],
  });
  return balance > 0n;
}

export type {Hex};
